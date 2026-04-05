package icap

import "net/http"

// ICAP protocol version.
const ICAPVersion = "ICAP/1.0"

// Request methods.
const (
	MethodREQMOD  = "REQMOD"
	MethodOPTIONS = "OPTIONS"
)

// Response status codes.
const (
	StatusOK             = 200
	StatusNoModification = 204
	StatusBadRequest     = 400
	StatusNotFound       = 404
	StatusServerError    = 500
)

// statusText maps ICAP status codes to reason phrases.
var statusText = map[int]string{
	StatusOK:             "OK",
	StatusNoModification: "No Modifications Needed",
	StatusBadRequest:     "Bad Request",
	StatusNotFound:       "Not Found",
	StatusServerError:    "Internal Server Error",
}

// StatusText returns the reason phrase for an ICAP status code.
func StatusText(code int) string {
	if t, ok := statusText[code]; ok {
		return t
	}
	return "Unknown"
}

// ICAPRequest represents a parsed ICAP request.
type ICAPRequest struct {
	Method  string
	URI     string
	Version string
	Headers map[string]string
	// For REQMOD: the encapsulated HTTP request.
	EncapsulatedReq *http.Request
	// Raw encapsulated request header bytes (for reconstruction).
	EncapsulatedReqHeader []byte
	EncapsulatedReqBody   []byte
}

// ICAPResponse is what we send back to Squid.
type ICAPResponse struct {
	StatusCode int
	Headers    map[string]string
	// Modified HTTP request to forward (nil means use 204 No Modification).
	ModifiedReq *http.Request
	// Optional: an HTTP error response to return instead of a modified request.
	// Used when we deny the request (403, 405, etc.).
	ErrorResp *http.Response
}
