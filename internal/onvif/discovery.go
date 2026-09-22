package onvif

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const discoveryAddress = "239.255.255.250:3702"

type discoveryServer struct {
	conn       *net.UDPConn
	deviceID   string
	serviceURL string
	name       string
	model      string
	logger     *slog.Logger
	once       sync.Once
}

func newDiscoveryServer(deviceID, serviceURL, name, model string, logger *slog.Logger) (*discoveryServer, error) {
	addr, err := net.ResolveUDPAddr("udp4", discoveryAddress)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(64 << 10)
	return &discoveryServer{conn: conn, deviceID: deviceID, serviceURL: serviceURL, name: name, model: model, logger: logger}, nil
}

func (d *discoveryServer) close() {
	d.once.Do(func() { _ = d.conn.Close() })
}

func (d *discoveryServer) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		d.close()
	}()

	buf := make([]byte, 64<<10)
	for {
		_ = d.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || isClosedNetworkError(err) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			d.logger.Warn("ONVIF discovery read failed", "error", err)
			continue
		}
		request := append([]byte(nil), buf[:n]...)
		response := d.response(request)
		if response == "" {
			continue
		}
		if _, err := d.conn.WriteToUDP([]byte(response), remote); err != nil {
			d.logger.Warn("ONVIF discovery response failed", "remote", remote, "error", err)
		}
	}
}

func isClosedNetworkError(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}

func (d *discoveryServer) response(request []byte) string {
	op, messageID, endpoint := discoveryRequest(request)
	if op == "" || op == "Resolve" && endpoint != d.deviceID {
		return ""
	}
	relates := xmlEscape(messageID)
	if relates == "" {
		relates = "urn:uuid:unknown"
	}
	match := fmt.Sprintf(`<a:EndpointReference><a:Address>%s</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types><d:Scopes>onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/%s onvif://www.onvif.org/hardware/%s</d:Scopes><d:XAddrs>%s</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion>`, xmlEscape(d.deviceID), xmlEscape(scopeValue(d.name)), xmlEscape(scopeValue(d.model)), xmlEscape(d.serviceURL))
	bodyName := "ProbeMatches"
	matchName := "ProbeMatch"
	if op == "Resolve" {
		bodyName, matchName = "ResolveMatches", "ResolveMatch"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Header><a:MessageID>` + newMessageID() + `</a:MessageID><a:RelatesTo>` + relates + `</a:RelatesTo><a:To s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/` + bodyName + `</a:Action></s:Header><s:Body><d:` + bodyName + `><d:` + matchName + `>` + match + `</d:` + matchName + `></d:` + bodyName + `></s:Body></s:Envelope>`
}

func discoveryRequest(body []byte) (operation, messageID, endpoint string) {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Probe", "Resolve":
			operation = start.Name.Local
		case "MessageID":
			_ = dec.DecodeElement(&messageID, &start)
		case "Address":
			_ = dec.DecodeElement(&endpoint, &start)
		}
	}
}

func scopeValue(s string) string {
	return strings.NewReplacer(" ", "_", "/", "_", "#", "_").Replace(s)
}

func newMessageID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("urn:uuid:%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
