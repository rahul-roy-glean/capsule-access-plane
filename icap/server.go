package icap

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// Server is an ICAP REQMOD server that validates and modifies HTTP requests
// on behalf of a Squid proxy.
type Server struct {
	Manifests manifest.Registry
	Providers *providers.Registry
	Logger    *slog.Logger

	listener net.Listener
}

// ListenAndServe starts the ICAP server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("icap: listen: %w", err)
	}
	s.listener = ln
	s.Logger.Info("ICAP server listening", "addr", ln.Addr().String())
	return s.Serve(ln)
}

// Serve accepts connections on the listener.
func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check for closed listener.
			if ne, ok := err.(*net.OpError); ok && !ne.Temporary() {
				return nil
			}
			s.Logger.Error("ICAP accept error", "err", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// Addr returns the listener address, or empty string if not listening.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Close shuts down the ICAP server listener.
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleConn processes ICAP requests on a single connection.
// ICAP connections may carry multiple requests (persistent connections),
// so we loop until the connection is closed or an error occurs.
func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	for {
		req, err := ParseRequest(br)
		if err != nil {
			// EOF is normal (client closed connection).
			if err.Error() != "icap parse: reading request line: EOF" {
				s.Logger.Debug("ICAP parse error", "err", err, "remote", conn.RemoteAddr())
			}
			return
		}

		var resp *ICAPResponse
		switch req.Method {
		case MethodOPTIONS:
			resp = s.handleOPTIONS(req)
		case MethodREQMOD:
			resp = s.handleREQMOD(req)
		default:
			s.Logger.Warn("ICAP unknown method", "method", req.Method)
			resp = &ICAPResponse{StatusCode: StatusNotFound}
		}

		if err := WriteResponse(conn, resp); err != nil {
			s.Logger.Error("ICAP write error", "err", err, "remote", conn.RemoteAddr())
			return
		}
	}
}
