package icap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// --- fake provider for tests ---

type fakeProvider struct {
	name  string
	hosts []string
	token string
}

func (p *fakeProvider) Name() string { return p.name }
func (p *fakeProvider) Type() string { return "fake" }
func (p *fakeProvider) Matches(host string) bool {
	for _, h := range p.hosts {
		if h == host {
			return true
		}
	}
	return false
}
func (p *fakeProvider) InjectCredentials(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+p.token)
	return nil
}
func (p *fakeProvider) ResolveToken(_ context.Context) (string, error) {
	return p.token, nil
}
func (p *fakeProvider) Start(_ context.Context) error { return nil }
func (p *fakeProvider) Stop()                         {}

// --- test helpers ---

// buildICAPRequest constructs a raw ICAP REQMOD request with an encapsulated HTTP request.
func buildICAPRequest(method, uri, httpMethod, httpPath, httpHost string, headers map[string]string, body string) string {
	// Build the encapsulated HTTP request.
	var httpReq bytes.Buffer
	fmt.Fprintf(&httpReq, "%s %s HTTP/1.1\r\n", httpMethod, httpPath)
	fmt.Fprintf(&httpReq, "Host: %s\r\n", httpHost)
	for k, v := range headers {
		fmt.Fprintf(&httpReq, "%s: %s\r\n", k, v)
	}
	if body != "" {
		fmt.Fprintf(&httpReq, "Content-Length: %d\r\n", len(body))
	}
	httpReq.WriteString("\r\n")

	headerBytes := httpReq.Bytes()
	headerLen := len(headerBytes)

	var icapBuf bytes.Buffer
	fmt.Fprintf(&icapBuf, "%s %s %s\r\n", method, uri, ICAPVersion)
	fmt.Fprintf(&icapBuf, "Host: icap-server\r\n")

	if body != "" {
		fmt.Fprintf(&icapBuf, "Encapsulated: req-hdr=0, req-body=%d\r\n", headerLen)
	} else {
		fmt.Fprintf(&icapBuf, "Encapsulated: req-hdr=0, null-body=%d\r\n", headerLen)
	}
	icapBuf.WriteString("\r\n")

	// Write encapsulated HTTP request headers.
	icapBuf.Write(headerBytes)

	// Write body in chunked encoding if present.
	if body != "" {
		fmt.Fprintf(&icapBuf, "%x\r\n", len(body))
		icapBuf.WriteString(body)
		icapBuf.WriteString("\r\n")
		icapBuf.WriteString("0\r\n")
		icapBuf.WriteString("\r\n")
	}

	return icapBuf.String()
}

func buildOPTIONSRequest(uri string) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "OPTIONS %s %s\r\n", uri, ICAPVersion)
	fmt.Fprintf(&buf, "Host: icap-server\r\n")
	buf.WriteString("\r\n")
	return buf.String()
}

func setupTestServer(t *testing.T, targetHost string, allowedIPs []string, fp *fakeProvider, constraints []manifest.MethodConstraint) *Server {
	t.Helper()

	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:         "test_api",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations: []manifest.Destination{
			{Host: targetHost, Port: 443, Protocol: "https", AllowedIPs: allowedIPs},
		},
		MethodConstraints: constraints,
	})

	provReg := providers.NewRegistry()
	if fp != nil {
		_ = provReg.Register(fp)
	}

	return &Server{
		Manifests: reg,
		Providers: provReg,
		Logger:    slog.Default(),
	}
}

func startTestServer(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })
	return ln.Addr().String()
}


// --- Parser tests ---

func TestParseRequest_OPTIONS(t *testing.T) {
	raw := buildOPTIONSRequest("icap://icap-server/reqmod")
	br := bufio.NewReader(strings.NewReader(raw))

	req, err := ParseRequest(br)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	if req.Method != MethodOPTIONS {
		t.Errorf("Method = %q, want %q", req.Method, MethodOPTIONS)
	}
	if req.URI != "icap://icap-server/reqmod" {
		t.Errorf("URI = %q, want icap://icap-server/reqmod", req.URI)
	}
	if req.Version != ICAPVersion {
		t.Errorf("Version = %q, want %q", req.Version, ICAPVersion)
	}
}

func TestParseRequest_REQMOD_NullBody(t *testing.T) {
	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"GET", "/api/v1/repos", "api.github.com",
		map[string]string{"X-Proxy-Token": "session-123"}, "")

	br := bufio.NewReader(strings.NewReader(raw))
	req, err := ParseRequest(br)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	if req.Method != MethodREQMOD {
		t.Errorf("Method = %q, want %q", req.Method, MethodREQMOD)
	}
	if req.EncapsulatedReq == nil {
		t.Fatal("EncapsulatedReq is nil")
	}
	if req.EncapsulatedReq.Method != "GET" {
		t.Errorf("HTTP Method = %q, want GET", req.EncapsulatedReq.Method)
	}
	if req.EncapsulatedReq.URL.Path != "/api/v1/repos" {
		t.Errorf("HTTP Path = %q, want /api/v1/repos", req.EncapsulatedReq.URL.Path)
	}
	if req.EncapsulatedReq.Host != "api.github.com" {
		t.Errorf("HTTP Host = %q, want api.github.com", req.EncapsulatedReq.Host)
	}
	if req.EncapsulatedReq.Header.Get("X-Proxy-Token") != "session-123" {
		t.Errorf("X-Proxy-Token = %q, want session-123", req.EncapsulatedReq.Header.Get("X-Proxy-Token"))
	}
	if req.EncapsulatedReqBody != nil {
		t.Errorf("expected nil body, got %d bytes", len(req.EncapsulatedReqBody))
	}
}

func TestParseRequest_REQMOD_WithBody(t *testing.T) {
	bodyContent := `{"name":"test-repo"}`
	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"POST", "/api/v1/repos", "api.github.com",
		nil, bodyContent)

	br := bufio.NewReader(strings.NewReader(raw))
	req, err := ParseRequest(br)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	if req.EncapsulatedReq.Method != "POST" {
		t.Errorf("HTTP Method = %q, want POST", req.EncapsulatedReq.Method)
	}

	if len(req.EncapsulatedReqBody) != len(bodyContent) {
		t.Errorf("body length = %d, want %d", len(req.EncapsulatedReqBody), len(bodyContent))
	}
	if string(req.EncapsulatedReqBody) != bodyContent {
		t.Errorf("body = %q, want %q", string(req.EncapsulatedReqBody), bodyContent)
	}
}

func TestParseRequest_Malformed(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"bad version", "REQMOD icap://x/y HTTP/1.1\r\n\r\n"},
		{"bad request line", "JUST-GARBAGE\r\n\r\n"},
		{"missing encapsulated", "REQMOD icap://x/y ICAP/1.0\r\nHost: x\r\n\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tt.input))
			_, err := ParseRequest(br)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestReadChunked(t *testing.T) {
	// "a\r\nhello worl\r\n" then "d\r\n" for remaining, but let's do a simple one.
	chunked := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(chunked))
	data, err := readChunked(br)
	if err != nil {
		t.Fatalf("readChunked: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("data = %q, want %q", string(data), "hello world")
	}
}

func TestReadChunked_Empty(t *testing.T) {
	chunked := "0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(chunked))
	data, err := readChunked(br)
	if err != nil {
		t.Fatalf("readChunked: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

// --- Server integration tests ---

func TestServer_OPTIONS(t *testing.T) {
	// Override DNS for SSRF check.
	origLookup := manifest.LookupHost
	manifest.LookupHost = func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	defer func() { manifest.LookupHost = origLookup }()

	s := setupTestServer(t, "api.github.com", nil, nil, nil)
	addr := startTestServer(t, s)

	raw := buildOPTIONSRequest("icap://icap-server/reqmod")
	resp := sendICAPRaw(t, addr, raw)

	if !strings.Contains(resp, "ICAP/1.0 200 OK") {
		t.Errorf("expected 200 OK, got:\n%s", resp)
	}
	if !strings.Contains(resp, "Methods: REQMOD") {
		t.Errorf("expected Methods: REQMOD in response:\n%s", resp)
	}
	if !strings.Contains(resp, "Allow: 204") {
		t.Errorf("expected Allow: 204 in response:\n%s", resp)
	}
}

func TestServer_REQMOD_CredentialInjection(t *testing.T) {
	origLookup := manifest.LookupHost
	manifest.LookupHost = func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	defer func() { manifest.LookupHost = origLookup }()

	fp := &fakeProvider{
		name:  "test",
		hosts: []string{"api.github.com"},
		token: "secret-token-123",
	}
	constraints := []manifest.MethodConstraint{
		{Method: "GET", PathPattern: "/**"},
	}
	s := setupTestServer(t, "api.github.com", nil, fp, constraints)
	addr := startTestServer(t, s)

	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"GET", "/api/v1/repos", "api.github.com",
		map[string]string{"X-Proxy-Token": "session-abc"}, "")

	resp := sendICAPRaw(t, addr, raw)

	if !strings.Contains(resp, "ICAP/1.0 200 OK") {
		t.Fatalf("expected 200 OK, got:\n%s", resp)
	}
	if !strings.Contains(resp, "Authorization: Bearer secret-token-123") {
		t.Errorf("expected injected Authorization header, got:\n%s", resp)
	}
	// X-Proxy-Token should be removed.
	if strings.Contains(resp, "X-Proxy-Token") {
		t.Errorf("X-Proxy-Token should be stripped from modified request, got:\n%s", resp)
	}
}

func TestServer_REQMOD_DeniedHost(t *testing.T) {
	origLookup := manifest.LookupHost
	manifest.LookupHost = func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	defer func() { manifest.LookupHost = origLookup }()

	// Server only allows api.github.com.
	s := setupTestServer(t, "api.github.com", nil, nil, nil)
	addr := startTestServer(t, s)

	// Request to a different host.
	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"GET", "/data", "evil.example.com",
		nil, "")

	resp := sendICAPRaw(t, addr, raw)

	// Should get ICAP 200 with HTTP 403 inside.
	if !strings.Contains(resp, "ICAP/1.0 200 OK") {
		t.Fatalf("expected ICAP 200 OK, got:\n%s", resp)
	}
	if !strings.Contains(resp, "403") {
		t.Errorf("expected HTTP 403 in response, got:\n%s", resp)
	}
	if !strings.Contains(resp, "not allowed by manifest") {
		t.Errorf("expected denial message, got:\n%s", resp)
	}
}

func TestServer_REQMOD_NoProvider_Returns204(t *testing.T) {
	origLookup := manifest.LookupHost
	manifest.LookupHost = func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	defer func() { manifest.LookupHost = origLookup }()

	// Host is allowed but no provider is registered.
	s := setupTestServer(t, "api.github.com", nil, nil, nil)
	addr := startTestServer(t, s)

	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"GET", "/data", "api.github.com",
		nil, "")

	resp := sendICAPRaw(t, addr, raw)

	if !strings.Contains(resp, "ICAP/1.0 204") {
		t.Errorf("expected 204 No Modification, got:\n%s", resp)
	}
}

func TestServer_REQMOD_DisallowedMethod(t *testing.T) {
	origLookup := manifest.LookupHost
	manifest.LookupHost = func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	defer func() { manifest.LookupHost = origLookup }()

	fp := &fakeProvider{
		name:  "test",
		hosts: []string{"api.github.com"},
		token: "secret",
	}
	// Only allow GET.
	constraints := []manifest.MethodConstraint{
		{Method: "GET", PathPattern: "/api/**"},
	}
	s := setupTestServer(t, "api.github.com", nil, fp, constraints)
	addr := startTestServer(t, s)

	// Send a DELETE request, which should be denied.
	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"DELETE", "/api/v1/repos/123", "api.github.com",
		nil, "")

	resp := sendICAPRaw(t, addr, raw)

	if !strings.Contains(resp, "ICAP/1.0 200 OK") {
		t.Fatalf("expected ICAP 200, got:\n%s", resp)
	}
	if !strings.Contains(resp, "405") {
		t.Errorf("expected HTTP 405 in response, got:\n%s", resp)
	}
	if !strings.Contains(resp, "not allowed by manifest") {
		t.Errorf("expected denial message, got:\n%s", resp)
	}
}

func TestServer_REQMOD_WithBody(t *testing.T) {
	origLookup := manifest.LookupHost
	manifest.LookupHost = func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	defer func() { manifest.LookupHost = origLookup }()

	fp := &fakeProvider{
		name:  "test",
		hosts: []string{"api.github.com"},
		token: "body-token",
	}
	constraints := []manifest.MethodConstraint{
		{Method: "POST", PathPattern: "/**"},
	}
	s := setupTestServer(t, "api.github.com", nil, fp, constraints)
	addr := startTestServer(t, s)

	bodyContent := `{"name":"test"}`
	raw := buildICAPRequest(MethodREQMOD, "icap://icap-server/reqmod",
		"POST", "/api/v1/repos", "api.github.com",
		nil, bodyContent)

	resp := sendICAPRaw(t, addr, raw)

	if !strings.Contains(resp, "ICAP/1.0 200 OK") {
		t.Fatalf("expected 200 OK, got:\n%s", resp)
	}
	if !strings.Contains(resp, "Authorization: Bearer body-token") {
		t.Errorf("expected injected credential, got:\n%s", resp)
	}
}

// --- Writer tests ---

func TestWriteResponse_204(t *testing.T) {
	var buf bytes.Buffer
	resp := &ICAPResponse{StatusCode: StatusNoModification}
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	expected := "ICAP/1.0 204 No Modifications Needed\r\n\r\n"
	if buf.String() != expected {
		t.Errorf("got:\n%q\nwant:\n%q", buf.String(), expected)
	}
}

func TestWriteResponse_OPTIONSBare(t *testing.T) {
	var buf bytes.Buffer
	resp := &ICAPResponse{
		StatusCode: StatusOK,
		Headers: map[string]string{
			"Methods": "REQMOD",
			"Allow":   "204",
		},
	}
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(out, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("unexpected prefix: %q", out)
	}
	if !strings.Contains(out, "Methods: REQMOD") {
		t.Errorf("missing Methods header: %q", out)
	}
	if !strings.Contains(out, "Allow: 204") {
		t.Errorf("missing Allow header: %q", out)
	}
}

func TestWriteResponse_WithModifiedRequest(t *testing.T) {
	var buf bytes.Buffer
	req, _ := http.NewRequest("GET", "http://api.github.com/repos", nil)
	req.Header.Set("Authorization", "Bearer token123")

	resp := &ICAPResponse{
		StatusCode:  StatusOK,
		ModifiedReq: req,
	}
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(out, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("unexpected prefix: %q", out)
	}
	if !strings.Contains(out, "Encapsulated: req-hdr=0, null-body=") {
		t.Errorf("missing Encapsulated header: %q", out)
	}
	if !strings.Contains(out, "Authorization: Bearer token123") {
		t.Errorf("missing Authorization header: %q", out)
	}
}

func TestWriteResponse_WithHTTPErrorResponse(t *testing.T) {
	var buf bytes.Buffer
	resp := &ICAPResponse{
		StatusCode: StatusOK,
		ErrorResp: &http.Response{
			StatusCode:    403,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain"}},
			Body:          io.NopCloser(strings.NewReader("forbidden")),
			ContentLength: 9,
		},
	}
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(out, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("unexpected prefix: %q", out)
	}
	if !strings.Contains(out, "403") {
		t.Errorf("expected 403 in encapsulated response: %q", out)
	}
	if !strings.Contains(out, "forbidden") {
		t.Errorf("expected error body: %q", out)
	}
}

// sendICAPRaw sends raw bytes to the ICAP server and reads the response.
func sendICAPRaw(t *testing.T, addr, raw string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Signal no more data will be written so server sees EOF after request.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(resp)
}
