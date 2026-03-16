package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/internal/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/providers"
)

type StreamEvent struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
}

type HTTPRequest struct {
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	InjectHeader  string            `json:"inject_header,omitempty"`
	InjectPrefix  string            `json:"inject_prefix,omitempty"`
}

type CLIRequest struct {
	Tool          string            `json:"tool"`
	Args          []string          `json:"args,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	CredentialEnv map[string]string `json:"credential_env,omitempty"`
}

type ExecuteRequest struct {
	Kind           policy.OperationKind `json:"kind"`
	CLI            *CLIRequest          `json:"cli,omitempty"`
	HTTP           *HTTPRequest         `json:"http,omitempty"`
	TimeoutSeconds int                  `json:"timeout_seconds,omitempty"`
	MaxOutputBytes int64                `json:"max_output_bytes,omitempty"`
	Stream         bool                 `json:"stream,omitempty"`
}

type ExecuteResult struct {
	ExitCode   int               `json:"exit_code,omitempty"`
	Stdout     string            `json:"stdout,omitempty"`
	Stderr     string            `json:"stderr,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	DurationMS int64             `json:"duration_ms"`
}

type Service struct {
	httpClient       *http.Client
	credentials      *providers.CredentialResolver
	defaultTimeout   time.Duration
	defaultMaxOutput int64
}

func NewService(credentialResolver *providers.CredentialResolver, defaultTimeout time.Duration, defaultMaxOutput int64) *Service {
	return &Service{
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		credentials:      credentialResolver,
		defaultTimeout:   defaultTimeout,
		defaultMaxOutput: defaultMaxOutput,
	}
}

func (s *Service) Execute(ctx context.Context, req ExecuteRequest) (*ExecuteResult, error) {
	switch req.Kind {
	case policy.OperationCLI:
		return s.executeCLI(ctx, req)
	case policy.OperationHTTP:
		return s.executeHTTP(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported execution kind %q", req.Kind)
	}
}

func (s *Service) Stream(ctx context.Context, req ExecuteRequest, writer io.Writer, flush func() error) (*ExecuteResult, error) {
	switch req.Kind {
	case policy.OperationCLI:
		return s.streamCLI(ctx, req, writer, flush)
	case policy.OperationHTTP:
		result, err := s.executeHTTP(ctx, req)
		if err != nil {
			return nil, err
		}
		_ = writeEvent(writer, flush, StreamEvent{Type: "result", Data: string(mustJSON(result))})
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported execution kind %q", req.Kind)
	}
}

func (s *Service) executeHTTP(ctx context.Context, req ExecuteRequest) (*ExecuteResult, error) {
	if req.HTTP == nil {
		return nil, fmt.Errorf("http request payload is required")
	}
	timeout := s.resolveTimeout(req.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, normalizeMethod(req.HTTP.Method), req.HTTP.URL, strings.NewReader(req.HTTP.Body))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	for key, value := range req.HTTP.Headers {
		httpReq.Header.Set(key, value)
	}
	if req.HTTP.CredentialRef != "" {
		token, err := s.credentials.Resolve(ctx, req.HTTP.CredentialRef)
		if err != nil {
			return nil, err
		}
		headerName := req.HTTP.InjectHeader
		if headerName == "" {
			headerName = "Authorization"
		}
		prefix := req.HTTP.InjectPrefix
		if prefix == "" {
			prefix = "Bearer "
		}
		httpReq.Header.Set(headerName, prefix+token)
	}

	start := time.Now()
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute http request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.resolveMaxOutput(req.MaxOutputBytes)))
	if err != nil {
		return nil, fmt.Errorf("read http response body: %w", err)
	}

	headers := make(map[string]string, len(resp.Header))
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	return &ExecuteResult{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(body),
		DurationMS: time.Since(start).Milliseconds(),
	}, nil
}

func (s *Service) executeCLI(ctx context.Context, req ExecuteRequest) (*ExecuteResult, error) {
	if req.CLI == nil {
		return nil, fmt.Errorf("cli request payload is required")
	}
	timeout := s.resolveTimeout(req.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	command := exec.CommandContext(ctx, req.CLI.Tool, req.CLI.Args...)
	if req.CLI.WorkingDir != "" {
		command.Dir = req.CLI.WorkingDir
	}
	command.Env = buildEnv(command.Env, req.CLI.Env)
	if len(req.CLI.CredentialEnv) > 0 {
		credentialEnv, err := s.resolveCredentialEnv(ctx, req.CLI.CredentialEnv)
		if err != nil {
			return nil, err
		}
		command.Env = buildEnv(command.Env, credentialEnv)
	}

	start := time.Now()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	var stdoutBuf limitedBuffer
	var stderrBuf limitedBuffer
	stdoutBuf.limit = s.resolveMaxOutput(req.MaxOutputBytes)
	stderrBuf.limit = s.resolveMaxOutput(req.MaxOutputBytes)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stdoutBuf, stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stderrBuf, stderr)
	}()

	waitErr := command.Wait()
	wg.Wait()

	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("wait for command: %w", waitErr)
		}
	}

	return &ExecuteResult{
		ExitCode:   exitCode,
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMS: time.Since(start).Milliseconds(),
	}, nil
}

func (s *Service) streamCLI(ctx context.Context, req ExecuteRequest, writer io.Writer, flush func() error) (*ExecuteResult, error) {
	if req.CLI == nil {
		return nil, fmt.Errorf("cli request payload is required")
	}
	timeout := s.resolveTimeout(req.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	command := exec.CommandContext(ctx, req.CLI.Tool, req.CLI.Args...)
	if req.CLI.WorkingDir != "" {
		command.Dir = req.CLI.WorkingDir
	}
	command.Env = buildEnv(command.Env, req.CLI.Env)
	if len(req.CLI.CredentialEnv) > 0 {
		credentialEnv, err := s.resolveCredentialEnv(ctx, req.CLI.CredentialEnv)
		if err != nil {
			return nil, err
		}
		command.Env = buildEnv(command.Env, credentialEnv)
	}

	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	start := time.Now()
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	var stdoutBuf limitedBuffer
	var stderrBuf limitedBuffer
	stdoutBuf.limit = s.resolveMaxOutput(req.MaxOutputBytes)
	stderrBuf.limit = s.resolveMaxOutput(req.MaxOutputBytes)

	var wg sync.WaitGroup
	streamPipe := func(eventType string, pipe io.Reader, sink *limitedBuffer) {
		defer wg.Done()
		buffer := make([]byte, 4096)
		for {
			n, readErr := pipe.Read(buffer)
			if n > 0 {
				chunk := string(buffer[:n])
				_, _ = sink.Write(buffer[:n])
				_ = writeEvent(writer, flush, StreamEvent{Type: eventType, Data: chunk})
			}
			if readErr != nil {
				return
			}
		}
	}

	wg.Add(2)
	go streamPipe("stdout", stdout, &stdoutBuf)
	go streamPipe("stderr", stderr, &stderrBuf)

	waitErr := command.Wait()
	wg.Wait()
	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("wait for command: %w", waitErr)
		}
	}
	result := &ExecuteResult{
		ExitCode:   exitCode,
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMS: time.Since(start).Milliseconds(),
	}
	if err := writeEvent(writer, flush, StreamEvent{Type: "result", Data: string(mustJSON(result))}); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) resolveCredentialEnv(ctx context.Context, refs map[string]string) (map[string]string, error) {
	resolved := make(map[string]string, len(refs))
	for key, ref := range refs {
		value, err := s.credentials.Resolve(ctx, ref)
		if err != nil {
			return nil, err
		}
		resolved[key] = value
	}
	return resolved, nil
}

func (s *Service) resolveTimeout(seconds int) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return s.defaultTimeout
}

func (s *Service) resolveMaxOutput(maxOutput int64) int64 {
	if maxOutput > 0 {
		return maxOutput
	}
	return s.defaultMaxOutput
}

func buildEnv(base []string, additions map[string]string) []string {
	if len(additions) == 0 {
		return base
	}
	for key, value := range additions {
		base = append(base, key+"="+value)
	}
	return base
}

func normalizeMethod(method string) string {
	if method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(method)
}

func writeEvent(writer io.Writer, flush func() error, event StreamEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := writer.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if flush != nil {
		return flush()
	}
	return nil
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int64
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.limit <= 0 {
		return l.buf.Write(p)
	}
	remaining := l.limit - int64(l.buf.Len())
	if remaining <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	return l.buf.Write(p)
}

func (l *limitedBuffer) String() string {
	return l.buf.String()
}
