package icap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ParseRequest reads a complete ICAP request from a buffered reader.
func ParseRequest(br *bufio.Reader) (*ICAPRequest, error) {
	// Read the request line: METHOD URI VERSION\r\n
	line, err := readLine(br)
	if err != nil {
		return nil, fmt.Errorf("icap parse: reading request line: %w", err)
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("icap parse: malformed request line: %q", line)
	}

	req := &ICAPRequest{
		Method:  parts[0],
		URI:     parts[1],
		Version: parts[2],
		Headers: make(map[string]string),
	}

	if req.Version != ICAPVersion {
		return nil, fmt.Errorf("icap parse: unsupported version %q", req.Version)
	}

	// Read ICAP headers until blank line.
	for {
		hline, err := readLine(br)
		if err != nil {
			return nil, fmt.Errorf("icap parse: reading header: %w", err)
		}
		if hline == "" {
			break
		}
		key, val, ok := strings.Cut(hline, ":")
		if !ok {
			return nil, fmt.Errorf("icap parse: malformed header: %q", hline)
		}
		req.Headers[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}

	// For OPTIONS there is no encapsulated section.
	if req.Method == MethodOPTIONS {
		return req, nil
	}

	// Parse the Encapsulated header to find offsets.
	encap, ok := req.Headers["Encapsulated"]
	if !ok {
		return nil, fmt.Errorf("icap parse: missing Encapsulated header")
	}

	offsets, err := parseEncapsulated(encap)
	if err != nil {
		return nil, fmt.Errorf("icap parse: %w", err)
	}

	// Read the encapsulated section.
	if err := readEncapsulated(br, req, offsets); err != nil {
		return nil, fmt.Errorf("icap parse: %w", err)
	}

	return req, nil
}

// encapEntry is a parsed component from the Encapsulated header.
type encapEntry struct {
	name   string // "req-hdr", "req-body", "null-body", etc.
	offset int
}

// parseEncapsulated parses "req-hdr=0, req-body=147" or "req-hdr=0, null-body=147".
func parseEncapsulated(value string) ([]encapEntry, error) {
	var entries []encapEntry
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, offStr, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed Encapsulated entry: %q", part)
		}
		off, err := strconv.Atoi(strings.TrimSpace(offStr))
		if err != nil {
			return nil, fmt.Errorf("invalid offset in Encapsulated: %q: %w", part, err)
		}
		entries = append(entries, encapEntry{name: strings.TrimSpace(name), offset: off})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("empty Encapsulated header")
	}
	return entries, nil
}

// readEncapsulated reads the encapsulated HTTP request from the ICAP body.
func readEncapsulated(br *bufio.Reader, req *ICAPRequest, entries []encapEntry) error {
	// Determine structure from entries.
	hasReqHdr := false
	hasReqBody := false
	hasNullBody := false
	reqHdrOffset := 0
	bodyOffset := 0

	for _, e := range entries {
		switch e.name {
		case "req-hdr":
			hasReqHdr = true
			reqHdrOffset = e.offset
		case "req-body":
			hasReqBody = true
			bodyOffset = e.offset
		case "null-body":
			hasNullBody = true
			bodyOffset = e.offset
		}
	}

	if !hasReqHdr {
		return fmt.Errorf("REQMOD without req-hdr in Encapsulated")
	}

	// The header section length is bodyOffset - reqHdrOffset.
	headerLen := bodyOffset - reqHdrOffset
	if headerLen <= 0 {
		return fmt.Errorf("invalid header length from Encapsulated offsets")
	}

	// Read the header section.
	headerBuf := make([]byte, headerLen)
	if _, err := io.ReadFull(br, headerBuf); err != nil {
		return fmt.Errorf("reading encapsulated header: %w", err)
	}
	req.EncapsulatedReqHeader = headerBuf

	// Read the body section (chunked or null-body).
	if hasReqBody {
		body, err := readChunked(br)
		if err != nil {
			return fmt.Errorf("reading chunked body: %w", err)
		}
		req.EncapsulatedReqBody = body
	} else if hasNullBody {
		req.EncapsulatedReqBody = nil
	}

	// Parse the encapsulated HTTP request from header bytes + body.
	httpReq, err := parseHTTPRequest(req.EncapsulatedReqHeader, req.EncapsulatedReqBody)
	if err != nil {
		return fmt.Errorf("parsing encapsulated HTTP request: %w", err)
	}
	req.EncapsulatedReq = httpReq

	return nil
}

// readChunked reads ICAP chunked encoding (same format as HTTP chunked).
// Each chunk: hex-size\r\n data\r\n, terminated by 0\r\n\r\n.
func readChunked(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := readLine(br)
		if err != nil {
			return nil, fmt.Errorf("reading chunk size: %w", err)
		}
		// Strip any chunk extensions after a semicolon.
		sizeStr, _, _ := strings.Cut(line, ";")
		sizeStr = strings.TrimSpace(sizeStr)

		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeStr, err)
		}
		if size == 0 {
			// Read the trailing \r\n after the 0-length chunk.
			_, _ = readLine(br)
			break
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, fmt.Errorf("reading chunk data: %w", err)
		}
		buf.Write(chunk)

		// Read trailing \r\n after chunk data.
		_, _ = readLine(br)
	}
	return buf.Bytes(), nil
}

// parseHTTPRequest reconstructs an *http.Request from raw header bytes and body.
func parseHTTPRequest(header, body []byte) (*http.Request, error) {
	var combined []byte
	combined = append(combined, header...)

	// http.ReadRequest reads the body from the reader based on Content-Length or
	// Transfer-Encoding, so we supply the body bytes after the header.
	if len(body) > 0 {
		combined = append(combined, body...)
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(combined)))
	if err != nil {
		return nil, err
	}

	// If we have body bytes, replace the body with a reader over them so it
	// can be read again during serialisation.
	if len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	return req, nil
}

// readLine reads a single \r\n-terminated line, stripping the terminator.
func readLine(br *bufio.Reader) (string, error) {
	var line strings.Builder
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\r' {
			// Peek at next byte for \n.
			next, err := br.ReadByte()
			if err != nil {
				return line.String(), nil
			}
			if next == '\n' {
				return line.String(), nil
			}
			// Not \n: put back and include \r.
			_ = br.UnreadByte()
			line.WriteByte(b)
		} else {
			line.WriteByte(b)
		}
	}
}
