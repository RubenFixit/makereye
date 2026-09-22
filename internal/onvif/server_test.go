package onvif

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MakerEyeLabs/makereye/internal/config"
)

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Device.Name = "mk4-bench"
	cfg.Stream.Name = "printer"
	cfg.Camera.Width = 1280
	cfg.Camera.Height = 720
	cfg.Camera.Framerate = 20
	cfg.Camera.BitrateKbps = 2500
	cfg.Go2rtc.RTSPListen = "0.0.0.0:8554"
	cfg.Go2rtc.Auth.Username = "protect"
	cfg.Go2rtc.Auth.Password = "secret"
	cfg.ONVIF.Enabled = true
	cfg.ONVIF.Listen = "0.0.0.0:8080"
	cfg.ONVIF.AdvertiseHost = "192.0.2.44"
	cfg.ONVIF.Username = "protect"
	cfg.ONVIF.Password = "secret"
	return cfg
}

func TestServiceAndStreamURLs(t *testing.T) {
	s := NewServer(testConfig(), nil)
	if got, want := s.ServiceURL(), "http://192.0.2.44:8080/onvif/device_service"; got != want {
		t.Fatalf("ServiceURL = %q, want %q", got, want)
	}
	if got, want := s.rtspURL(), "rtsp://192.0.2.44:8554/printer"; got != want {
		t.Fatalf("rtspURL = %q, want %q", got, want)
	}
}

func TestUsernameTokenDigest(t *testing.T) {
	now := time.Date(2026, 9, 22, 20, 0, 0, 0, time.UTC)
	nonce := []byte("0123456789abcdef")
	created := now.Format(time.RFC3339)
	h := sha1.New()
	_, _ = h.Write(nonce)
	_, _ = h.Write([]byte(created))
	_, _ = h.Write([]byte("secret"))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	body := []byte(fmt.Sprintf(`<UsernameToken><Username>protect</Username><Password Type="x#PasswordDigest">%s</Password><Nonce>%s</Nonce><Created>%s</Created></UsernameToken>`, digest, base64.StdEncoding.EncodeToString(nonce), created))
	if err := authenticate(body, "protect", "secret", now); err != nil {
		t.Fatalf("authenticate valid digest: %v", err)
	}
	if err := authenticate(body, "protect", "wrong", now); err == nil {
		t.Fatal("authenticate accepted wrong password")
	}
	if err := authenticate(body, "protect", "secret", now.Add(10*time.Minute)); err == nil {
		t.Fatal("authenticate accepted stale timestamp")
	}
}

func TestSOAPGetStreamURI(t *testing.T) {
	s := NewServer(testConfig(), nil)
	created := time.Now().UTC().Format(time.RFC3339Nano)
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security><UsernameToken><Username>protect</Username><Password Type="x#PasswordText">secret</Password><Created>` + created + `</Created></UsernameToken></Security></s:Header><s:Body><GetStreamUri/></s:Body></s:Envelope>`
	req := httptest.NewRequest(http.MethodPost, devicePath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleSOAP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rtsp://192.0.2.44:8554/printer") {
		t.Fatalf("response missing RTSP URI: %s", rec.Body.String())
	}
}

func TestSOAPRejectsMissingCredentials(t *testing.T) {
	s := NewServer(testConfig(), nil)
	req := httptest.NewRequest(http.MethodPost, devicePath, strings.NewReader(`<Envelope><Body><GetProfiles/></Body></Envelope>`))
	rec := httptest.NewRecorder()
	s.handleSOAP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSOAPAcceptsHTTPDigest(t *testing.T) {
	s := NewServer(testConfig(), nil)
	uri, nc, cnonce := devicePath, "00000001", "client-nonce"
	ha1 := md5Hex("protect:MakerEye:secret")
	ha2 := md5Hex(http.MethodPost + ":" + uri)
	response := md5Hex(strings.Join([]string{ha1, s.httpNonce, nc, cnonce, "auth", ha2}, ":"))
	authorization := fmt.Sprintf(`Digest username="protect", realm="MakerEye", nonce="%s", uri="%s", qop=auth, nc=%s, cnonce="%s", response="%s"`, s.httpNonce, uri, nc, cnonce, response)

	req := httptest.NewRequest(http.MethodPost, uri, strings.NewReader(`<Envelope><Body><GetProfiles/></Body></Envelope>`))
	req.Header.Set("Authorization", authorization)
	rec := httptest.NewRecorder()
	s.handleSOAP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestDiscoveryProbeResponse(t *testing.T) {
	d := &discoveryServer{deviceID: "urn:uuid:test-device", serviceURL: "http://192.0.2.44:8080/onvif/device_service", name: "mk4-bench", model: "MakerEye"}
	probe := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><MessageID>urn:uuid:request-1</MessageID></s:Header><s:Body><Probe/></s:Body></s:Envelope>`)
	got := d.response(probe)
	for _, want := range []string{"ProbeMatches", "urn:uuid:request-1", "urn:uuid:test-device", d.serviceURL, "NetworkVideoTransmitter"} {
		if !strings.Contains(got, want) {
			t.Errorf("discovery response missing %q: %s", want, got)
		}
	}
}
