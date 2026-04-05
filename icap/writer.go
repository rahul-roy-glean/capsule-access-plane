package icap

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// WriteResponse writes an ICAP response to the writer.
func WriteResponse(w io.Writer, resp *ICAPResponse) error {
	// 204 No Modification: minimal response.
	if resp.StatusCode == StatusNoModification {
		return writeNoModification(w)
	}

	// If there is an HTTP error response (e.g. 403, 405), encapsulate it.
	if resp.ErrorResp != nil {
		return writeWithHTTPResponse(w, resp)
	}

	// If there is a modified HTTP request, encapsulate it.
	if resp.ModifiedReq != nil {
		return writeWithHTTPRequest(w, resp)
	}

	// Bare ICAP response (e.g. OPTIONS response).
	return writeBareResponse(w, resp)
}

// writeNoModification writes a 204 response.
func writeNoModification(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s %d %s\r\n\r\n",
		ICAPVersion, StatusNoModification, StatusText(StatusNoModification))
	return err
}

// writeBareResponse writes an ICAP response with headers but no encapsulated body.
// Used for OPTIONS responses.
func writeBareResponse(w io.Writer, resp *ICAPResponse) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", ICAPVersion, resp.StatusCode, StatusText(resp.StatusCode))
	writeHeaders(&buf, resp.Headers)
	buf.WriteString("\r\n")
	_, err := w.Write(buf.Bytes())
	return err
}

// writeWithHTTPRequest writes an ICAP 200 response encapsulating a modified HTTP request.
func writeWithHTTPRequest(w io.Writer, resp *ICAPResponse) error {
	req := resp.ModifiedReq

	// Serialise the HTTP request line + headers.
	var reqHeader bytes.Buffer
	fmt.Fprintf(&reqHeader, "%s %s %s\r\n", req.Method, requestURI(req), req.Proto)
	writeHTTPHeaders(&reqHeader, req.Header, req.Host)
	reqHeader.WriteString("\r\n")

	// Read the body if present.
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("icap write: reading request body: %w", err)
		}
	}

	headerBytes := reqHeader.Bytes()
	hasBody := len(body) > 0

	// Build the ICAP response.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", ICAPVersion, resp.StatusCode, StatusText(resp.StatusCode))

	if hasBody {
		fmt.Fprintf(&buf, "Encapsulated: req-hdr=0, req-body=%d\r\n", len(headerBytes))
	} else {
		fmt.Fprintf(&buf, "Encapsulated: req-hdr=0, null-body=%d\r\n", len(headerBytes))
	}
	writeHeaders(&buf, resp.Headers)
	buf.WriteString("\r\n")

	// Write encapsulated HTTP request headers.
	buf.Write(headerBytes)

	// Write body in chunked encoding if present.
	if hasBody {
		writeChunked(&buf, body)
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// writeWithHTTPResponse writes an ICAP 200 response encapsulating an HTTP response
// (used for error responses like 403, 405).
func writeWithHTTPResponse(w io.Writer, resp *ICAPResponse) error {
	httpResp := resp.ErrorResp

	// Serialise the HTTP response.
	var respBuf bytes.Buffer
	if err := httpResp.Write(&respBuf); err != nil {
		return fmt.Errorf("icap write: serialising HTTP response: %w", err)
	}

	respBytes := respBuf.Bytes()

	// For simplicity we encapsulate the entire HTTP response as res-hdr + null-body.
	// We need to find where the response headers end and body begins.
	// However, the simplest approach is to use res-hdr=0, res-body=N.
	// But since http.Response.Write includes the body, we split on \r\n\r\n.
	headerEnd := bytes.Index(respBytes, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return fmt.Errorf("icap write: cannot find end of HTTP response headers")
	}
	hdrLen := headerEnd + 4 // include the \r\n\r\n
	bodyPart := respBytes[hdrLen:]

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", ICAPVersion, resp.StatusCode, StatusText(resp.StatusCode))

	if len(bodyPart) > 0 {
		fmt.Fprintf(&buf, "Encapsulated: res-hdr=0, res-body=%d\r\n", hdrLen)
	} else {
		fmt.Fprintf(&buf, "Encapsulated: res-hdr=0, null-body=%d\r\n", hdrLen)
	}
	writeHeaders(&buf, resp.Headers)
	buf.WriteString("\r\n")

	// Write the HTTP response headers.
	buf.Write(respBytes[:hdrLen])

	// Write body in chunked encoding if present.
	if len(bodyPart) > 0 {
		writeChunked(&buf, bodyPart)
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// writeChunked writes data in HTTP chunked encoding.
func writeChunked(buf *bytes.Buffer, data []byte) {
	fmt.Fprintf(buf, "%x\r\n", len(data))
	buf.Write(data)
	buf.WriteString("\r\n")
	buf.WriteString("0\r\n")
	buf.WriteString("\r\n")
}

// writeHeaders writes ICAP headers from a map. Skips Encapsulated (handled separately).
func writeHeaders(buf *bytes.Buffer, headers map[string]string) {
	if headers == nil {
		return
	}
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "Encapsulated") {
			continue // written separately
		}
		fmt.Fprintf(buf, "%s: %s\r\n", k, headers[k])
	}
}

// writeHTTPHeaders writes HTTP headers in wire format. Ensures Host is present.
func writeHTTPHeaders(buf *bytes.Buffer, headers http.Header, host string) {
	if host != "" {
		fmt.Fprintf(buf, "Host: %s\r\n", host)
	}
	// Sort for deterministic output.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if strings.EqualFold(k, "Host") {
			continue // already written
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range headers[k] {
			fmt.Fprintf(buf, "%s: %s\r\n", k, v)
		}
	}
}

// requestURI returns the Request-URI for the HTTP request line.
func requestURI(req *http.Request) string {
	if req.URL == nil {
		return "/"
	}
	uri := req.URL.RequestURI()
	if uri == "" {
		return "/"
	}
	return uri
}
