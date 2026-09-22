// Package onvif exposes MakerEye's existing go2rtc RTSP stream through the
// small ONVIF device/media surface used by NVRs such as UniFi Protect.
// It never opens the camera or handles video frames itself.
package onvif

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MakerEyeLabs/makereye/internal/config"
	"github.com/MakerEyeLabs/makereye/internal/go2rtc"
	"github.com/MakerEyeLabs/makereye/internal/version"
)

const (
	devicePath = "/onvif/device_service"
	mediaPath  = "/onvif/media_service"
	maxBody    = 1 << 20
	clockSkew  = 5 * time.Minute
)

// Server owns the ONVIF HTTP and WS-Discovery listeners.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	deviceID  string
	httpNonce string
	http      *http.Server
	listener  net.Listener
	discovery *discoveryServer

	mu      sync.Mutex
	started bool
}

// NewServer constructs an ONVIF server without opening sockets.
func NewServer(cfg *config.Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger, deviceID: deviceID(cfg.Device.Name), httpNonce: strings.TrimPrefix(newMessageID(), "urn:uuid:")}
}

// Start begins the HTTP SOAP service and WS-Discovery responder.
func (s *Server) Start(ctx context.Context) error {
	if !s.cfg.ONVIF.Enabled {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("onvif server is already running")
	}

	listener, err := net.Listen("tcp", s.cfg.ONVIF.Listen)
	if err != nil {
		return fmt.Errorf("listening for ONVIF HTTP on %s: %w", s.cfg.ONVIF.Listen, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(devicePath, s.handleSOAP)
	mux.HandleFunc(mediaPath, s.handleSOAP)
	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	discovery, err := newDiscoveryServer(s.deviceID, s.serviceURL(), s.cfg.Device.Name, s.cfg.ONVIF.Model, s.logger)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("starting ONVIF discovery: %w", err)
	}

	s.listener = listener
	s.http = httpServer
	s.discovery = discovery
	s.started = true

	go func() {
		if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("ONVIF HTTP server stopped", "error", err)
		}
	}()
	go discovery.serve(ctx)

	s.logger.Info("ONVIF started", "service", s.serviceURL(), "device_id", s.deviceID)
	return nil
}

// Stop closes both ONVIF listeners.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	httpServer := s.http
	discovery := s.discovery
	s.started = false
	s.mu.Unlock()

	if discovery != nil {
		discovery.close()
	}
	if httpServer != nil {
		return httpServer.Shutdown(ctx)
	}
	return nil
}

// ServiceURL is the LAN-reachable ONVIF device-service URL.
func (s *Server) ServiceURL() string { return s.serviceURL() }

func (s *Server) serviceURL() string {
	_, port, err := net.SplitHostPort(s.cfg.ONVIF.Listen)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("http://%s%s", net.JoinHostPort(s.advertiseHost(), port), devicePath)
}

func (s *Server) mediaURL() string {
	return strings.TrimSuffix(s.serviceURL(), devicePath) + mediaPath
}

func (s *Server) advertiseHost() string {
	if host := strings.TrimSpace(s.cfg.ONVIF.AdvertiseHost); host != "" {
		return strings.Trim(host, "[]")
	}
	host, _, err := net.SplitHostPort(s.cfg.ONVIF.Listen)
	if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		return host
	}
	host, _, err = net.SplitHostPort(go2rtc.AdvertiseHostPort(s.cfg.Go2rtc.RTSPListen))
	if err == nil {
		return host
	}
	return "127.0.0.1"
}

func (s *Server) rtspURL() string {
	_, port, err := net.SplitHostPort(s.cfg.Go2rtc.RTSPListen)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("rtsp://%s/%s", net.JoinHostPort(s.advertiseHost(), port), url.PathEscape(s.cfg.Stream.Name))
}

func (s *Server) handleSOAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ONVIF services require POST", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request", http.StatusBadRequest)
		return
	}
	op := operation(raw)
	if op == "" {
		http.Error(w, "malformed ONVIF request", http.StatusBadRequest)
		return
	}

	// Clients commonly need the device clock before constructing a digest.
	if op != "GetSystemDateAndTime" {
		wsErr := authenticate(raw, s.cfg.ONVIF.Username, s.cfg.ONVIF.Password, time.Now())
		httpOK := s.authenticateHTTP(r)
		if wsErr != nil && !httpOK {
			s.logger.Warn("ONVIF authentication failed", "operation", op, "remote", r.RemoteAddr, "error", wsErr)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="MakerEye", nonce="%s", algorithm=MD5, qop="auth"`, s.httpNonce))
			http.Error(w, "ONVIF authentication failed", http.StatusUnauthorized)
			return
		}
	}

	response, err := s.response(op, raw)
	if err != nil {
		s.logger.Debug("unsupported ONVIF operation", "operation", op, "error", err)
		writeFault(w, "ter:ActionNotSupported", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = w.Write([]byte(response))
}

func (s *Server) authenticateHTTP(r *http.Request) bool {
	if username, password, ok := r.BasicAuth(); ok {
		return constantEqual(username, s.cfg.ONVIF.Username) && constantEqual(password, s.cfg.ONVIF.Password)
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "digest ") {
		return false
	}
	fields := parseDigestFields(strings.TrimSpace(auth[len("Digest "):]))
	if !constantEqual(fields["username"], s.cfg.ONVIF.Username) || fields["realm"] != "MakerEye" || fields["nonce"] != s.httpNonce || fields["uri"] != r.URL.RequestURI() {
		return false
	}
	ha1 := md5Hex(s.cfg.ONVIF.Username + ":MakerEye:" + s.cfg.ONVIF.Password) // MD5 is required by legacy HTTP Digest.
	ha2 := md5Hex(r.Method + ":" + fields["uri"])
	want := ""
	if fields["qop"] == "auth" {
		if fields["nc"] == "" || fields["cnonce"] == "" {
			return false
		}
		want = md5Hex(strings.Join([]string{ha1, s.httpNonce, fields["nc"], fields["cnonce"], "auth", ha2}, ":"))
	} else if fields["qop"] == "" {
		want = md5Hex(ha1 + ":" + s.httpNonce + ":" + ha2)
	} else {
		return false
	}
	return constantEqual(fields["response"], want)
}

func parseDigestFields(value string) map[string]string {
	fields := make(map[string]string)
	for len(value) > 0 {
		value = strings.TrimLeft(value, " ,")
		eq := strings.IndexByte(value, '=')
		if eq <= 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(value[:eq]))
		value = strings.TrimSpace(value[eq+1:])
		var field string
		if strings.HasPrefix(value, `"`) {
			value = value[1:]
			end := strings.IndexByte(value, '"')
			if end < 0 {
				break
			}
			field, value = value[:end], value[end+1:]
		} else {
			end := strings.IndexByte(value, ',')
			if end < 0 {
				field, value = value, ""
			} else {
				field, value = value[:end], value[end+1:]
			}
		}
		fields[key] = strings.TrimSpace(field)
	}
	return fields
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func operation(body []byte) string {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if start, ok := tok.(xml.StartElement); ok && supportedOperations[start.Name.Local] {
			return start.Name.Local
		}
	}
}

var supportedOperations = map[string]bool{
	"GetDeviceInformation": true, "GetSystemDateAndTime": true,
	"GetCapabilities": true, "GetServices": true, "GetScopes": true,
	"GetDiscoveryMode": true, "GetVideoSources": true, "GetProfiles": true,
	"GetProfile": true, "GetVideoEncoderConfiguration": true,
	"GetVideoEncoderConfigurations": true, "GetVideoEncoderConfigurationOptions": true,
	"GetStreamUri": true,
}

type credentials struct {
	Username     string
	Password     string
	PasswordType string
	Nonce        string
	Created      string
}

func authenticate(body []byte, wantUser, wantPassword string, now time.Time) error {
	var got credentials
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var value string
		switch start.Name.Local {
		case "Username", "Password", "Nonce", "Created":
			if err := dec.DecodeElement(&value, &start); err != nil {
				return fmt.Errorf("invalid UsernameToken")
			}
		}
		switch start.Name.Local {
		case "Username":
			got.Username = value
		case "Password":
			got.Password = value
			for _, attr := range start.Attr {
				if attr.Name.Local == "Type" {
					got.PasswordType = attr.Value
				}
			}
		case "Nonce":
			got.Nonce = value
		case "Created":
			got.Created = value
		}
	}
	if subtle.ConstantTimeCompare([]byte(got.Username), []byte(wantUser)) != 1 {
		return fmt.Errorf("invalid username")
	}
	if strings.HasSuffix(got.PasswordType, "#PasswordDigest") || got.Nonce != "" {
		created, err := time.Parse(time.RFC3339Nano, got.Created)
		if err != nil || created.Before(now.Add(-clockSkew)) || created.After(now.Add(clockSkew)) {
			return fmt.Errorf("invalid or stale timestamp")
		}
		nonce, err := base64.StdEncoding.DecodeString(got.Nonce)
		if err != nil {
			return fmt.Errorf("invalid nonce")
		}
		h := sha1.New() // SHA-1 is mandated by ONVIF UsernameToken PasswordDigest.
		_, _ = h.Write(nonce)
		_, _ = h.Write([]byte(got.Created))
		_, _ = h.Write([]byte(wantPassword))
		want := base64.StdEncoding.EncodeToString(h.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(got.Password), []byte(want)) != 1 {
			return fmt.Errorf("invalid password digest")
		}
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(got.Password), []byte(wantPassword)) != 1 {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func deviceID(name string) string {
	seed, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(strings.TrimSpace(string(seed))) == 0 {
		seed = []byte(name)
	}
	sum := sha1.Sum(append(seed, []byte("\x00"+name)...))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func writeFault(w http.ResponseWriter, code, reason string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, envelope(`<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>%s</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="en">%s</s:Text></s:Reason></s:Fault>`), code, xmlEscape(reason))
}

func envelope(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:ter="http://www.onvif.org/ver10/error"><s:Body>` + body + `</s:Body></s:Envelope>`
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (s *Server) response(op string, request []byte) (string, error) {
	w, h, fps, kbps := s.cfg.Camera.Width, s.cfg.Camera.Height, s.cfg.Camera.Framerate, s.cfg.Camera.BitrateKbps
	name, token := xmlEscape(s.cfg.Stream.Name), xmlEscape(s.cfg.Stream.Name)
	deviceURL, mediaURL, rtspURL := xmlEscape(s.serviceURL()), xmlEscape(s.mediaURL()), xmlEscape(s.rtspURL())

	switch op {
	case "GetDeviceInformation":
		return envelope(fmt.Sprintf(`<tds:GetDeviceInformationResponse><tds:Manufacturer>%s</tds:Manufacturer><tds:Model>%s</tds:Model><tds:FirmwareVersion>%s</tds:FirmwareVersion><tds:SerialNumber>%s</tds:SerialNumber><tds:HardwareId>raspberry-pi</tds:HardwareId></tds:GetDeviceInformationResponse>`, xmlEscape(s.cfg.ONVIF.Manufacturer), xmlEscape(s.cfg.ONVIF.Model), xmlEscape(version.Version), xmlEscape(s.deviceID))), nil
	case "GetSystemDateAndTime":
		now := time.Now()
		utc, local := dateTimeXML(now.UTC()), dateTimeXML(now)
		return envelope(fmt.Sprintf(`<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:TimeZone><tt:TZ>%s</tt:TZ></tt:TimeZone><tt:UTCDateTime>%s</tt:UTCDateTime><tt:LocalDateTime>%s</tt:LocalDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>`, xmlEscape(now.Format("MST-07:00")), utc, local)), nil
	case "GetCapabilities":
		return envelope(fmt.Sprintf(`<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Device><tt:XAddr>%s</tt:XAddr><tt:Network IPFilter="false" ZeroConfiguration="false" IPVersion6="false" DynDNS="false" Dot11Configuration="false" HostnameFromDHCP="false" NTP="1" DHCPv6="false"/></tt:Device><tt:Media><tt:XAddr>%s</tt:XAddr><tt:StreamingCapabilities RTPMulticast="false" RTP_TCP="true" RTP_RTSP_TCP="true" NonAggregateControl="false" NoRTSPStreaming="false"/></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>`, deviceURL, mediaURL)), nil
	case "GetServices":
		return envelope(fmt.Sprintf(`<tds:GetServicesResponse><tds:Service><tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace><tds:XAddr>%s</tds:XAddr><tds:Version><tt:Major>2</tt:Major><tt:Minor>20</tt:Minor></tds:Version></tds:Service><tds:Service><tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace><tds:XAddr>%s</tds:XAddr><tds:Version><tt:Major>2</tt:Major><tt:Minor>10</tt:Minor></tds:Version></tds:Service></tds:GetServicesResponse>`, deviceURL, mediaURL)), nil
	case "GetScopes":
		return envelope(fmt.Sprintf(`<tds:GetScopesResponse><tds:Scopes><tt:ScopeDef>Fixed</tt:ScopeDef><tt:ScopeItem>onvif://www.onvif.org/Profile/Streaming</tt:ScopeItem></tds:Scopes><tds:Scopes><tt:ScopeDef>Configurable</tt:ScopeDef><tt:ScopeItem>onvif://www.onvif.org/name/%s</tt:ScopeItem></tds:Scopes><tds:Scopes><tt:ScopeDef>Fixed</tt:ScopeDef><tt:ScopeItem>onvif://www.onvif.org/hardware/%s</tt:ScopeItem></tds:Scopes></tds:GetScopesResponse>`, url.PathEscape(s.cfg.Device.Name), url.PathEscape(s.cfg.ONVIF.Model))), nil
	case "GetDiscoveryMode":
		return envelope(`<tds:GetDiscoveryModeResponse><tds:DiscoveryMode>Discoverable</tds:DiscoveryMode></tds:GetDiscoveryModeResponse>`), nil
	case "GetVideoSources":
		return envelope(fmt.Sprintf(`<trt:GetVideoSourcesResponse><trt:VideoSources token="source-%s"><tt:Framerate>%d</tt:Framerate><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution></trt:VideoSources></trt:GetVideoSourcesResponse>`, token, fps, w, h)), nil
	case "GetProfiles", "GetProfile":
		if op == "GetProfiles" {
			return envelope(`<trt:GetProfilesResponse>` + profileXML("Profiles", name, token, w, h, fps, kbps) + `</trt:GetProfilesResponse>`), nil
		}
		return envelope(`<trt:GetProfileResponse>` + profileXML("Profile", name, token, w, h, fps, kbps) + `</trt:GetProfileResponse>`), nil
	case "GetVideoEncoderConfiguration", "GetVideoEncoderConfigurations":
		if op == "GetVideoEncoderConfigurations" {
			return envelope(`<trt:GetVideoEncoderConfigurationsResponse><trt:Configurations token="encoder-` + token + `">` + encoderFields(name, w, h, fps, kbps) + `</trt:Configurations></trt:GetVideoEncoderConfigurationsResponse>`), nil
		}
		return envelope(`<trt:GetVideoEncoderConfigurationResponse><trt:Configuration token="encoder-` + token + `">` + encoderFields(name, w, h, fps, kbps) + `</trt:Configuration></trt:GetVideoEncoderConfigurationResponse>`), nil
	case "GetVideoEncoderConfigurationOptions":
		return envelope(fmt.Sprintf(`<trt:GetVideoEncoderConfigurationOptionsResponse><trt:Options><tt:QualityRange><tt:Min>1</tt:Min><tt:Max>10</tt:Max></tt:QualityRange><tt:H264><tt:ResolutionsAvailable><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:ResolutionsAvailable><tt:GovLengthRange><tt:Min>1</tt:Min><tt:Max>300</tt:Max></tt:GovLengthRange><tt:FrameRateRange><tt:Min>1</tt:Min><tt:Max>%d</tt:Max></tt:FrameRateRange><tt:EncodingIntervalRange><tt:Min>1</tt:Min><tt:Max>1</tt:Max></tt:EncodingIntervalRange><tt:H264ProfilesSupported>Main</tt:H264ProfilesSupported></tt:H264></trt:Options></trt:GetVideoEncoderConfigurationOptionsResponse>`, w, h, fps)), nil
	case "GetStreamUri":
		return envelope(fmt.Sprintf(`<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>%s</tt:Uri><tt:InvalidAfterConnect>false</tt:InvalidAfterConnect><tt:InvalidAfterReboot>false</tt:InvalidAfterReboot><tt:Timeout>PT0S</tt:Timeout></trt:MediaUri></trt:GetStreamUriResponse>`, rtspURL)), nil
	default:
		return "", fmt.Errorf("operation %q is not implemented", op)
	}
}

func dateTimeXML(t time.Time) string {
	return fmt.Sprintf(`<tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time><tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date>`, t.Hour(), t.Minute(), t.Second(), t.Year(), t.Month(), t.Day())
}

func profileXML(element, name, token string, w, h, fps, kbps int) string {
	return fmt.Sprintf(`<trt:%s token="%s" fixed="true"><tt:Name>%s</tt:Name><tt:VideoSourceConfiguration token="source-config-%s"><tt:Name>%s</tt:Name><tt:UseCount>1</tt:UseCount><tt:SourceToken>source-%s</tt:SourceToken><tt:Bounds x="0" y="0" width="%d" height="%d"/></tt:VideoSourceConfiguration><tt:VideoEncoderConfiguration token="encoder-%s">%s</tt:VideoEncoderConfiguration></trt:%s>`, element, token, name, token, name, token, w, h, token, encoderFields(name, w, h, fps, kbps), element)
}

func encoderFields(name string, w, h, fps, kbps int) string {
	return fmt.Sprintf(`<tt:Name>%s</tt:Name><tt:UseCount>1</tt:UseCount><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution><tt:Quality>5</tt:Quality><tt:RateControl><tt:FrameRateLimit>%d</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>%d</tt:BitrateLimit></tt:RateControl><tt:H264><tt:GovLength>%d</tt:GovLength><tt:H264Profile>Main</tt:H264Profile></tt:H264><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>0</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT60S</tt:SessionTimeout>`, name, w, h, fps, kbps, fps)
}
