package policy

import (
	"fmt"
	"net/url"
	"strings"
)

type OperationKind string

const (
	OperationCLI  OperationKind = "cli"
	OperationHTTP OperationKind = "http"
)

type ActorContext struct {
	UserID          string `json:"user_id"`
	VirtualIdentity string `json:"virtual_identity,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
}

type ExecutionPolicyInput struct {
	Kind       OperationKind
	Tool       string
	URL        string
	IsWrite    bool
	Actor      ActorContext
	AllowHosts []string
}

type Engine struct {
	allowedCLITools map[string]struct{}
}

func NewEngine(allowedCLITools []string) *Engine {
	tools := make(map[string]struct{}, len(allowedCLITools))
	for _, tool := range allowedCLITools {
		tool = strings.TrimSpace(tool)
		if tool != "" {
			tools[tool] = struct{}{}
		}
	}
	return &Engine{allowedCLITools: tools}
}

func (e *Engine) AllowExecution(input ExecutionPolicyInput) (string, error) {
	switch input.Kind {
	case OperationCLI:
		if _, ok := e.allowedCLITools[input.Tool]; !ok {
			return "", fmt.Errorf("tool %q is not allowed for remote execution", input.Tool)
		}
		if input.Actor.UserID == "" {
			return "", fmt.Errorf("actor_context.user_id is required for CLI execution")
		}
		return "allowed", nil
	case OperationHTTP:
		parsed, err := url.Parse(input.URL)
		if err != nil {
			return "", fmt.Errorf("invalid url: %w", err)
		}
		if parsed.Scheme != "https" {
			return "", fmt.Errorf("only https URLs are allowed")
		}
		if len(input.AllowHosts) > 0 && !containsHost(input.AllowHosts, parsed.Hostname()) {
			return "", fmt.Errorf("host %q is not in the allowlist", parsed.Hostname())
		}
		if input.Actor.UserID == "" {
			return "", fmt.Errorf("actor_context.user_id is required for HTTP execution")
		}
		return "allowed", nil
	default:
		return "", fmt.Errorf("unsupported operation kind %q", input.Kind)
	}
}

func (e *Engine) AllowGrant(hosts []string, scope string, actor ActorContext) error {
	if actor.UserID == "" {
		return fmt.Errorf("actor_context.user_id is required for grants")
	}
	if len(hosts) == 0 {
		return fmt.Errorf("at least one host is required")
	}
	if scope == "" {
		return fmt.Errorf("scope is required")
	}
	return nil
}

func containsHost(allowHosts []string, host string) bool {
	for _, candidate := range allowHosts {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if host == candidate {
			return true
		}
		if strings.HasPrefix(candidate, "*.") && strings.HasSuffix(host, strings.TrimPrefix(candidate, "*")) {
			return true
		}
	}
	return false
}
