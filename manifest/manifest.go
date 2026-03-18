package manifest

import "github.com/rahul-roy-glean/capsule-access-plane/accessplane"

// ToolManifest describes the capabilities and access patterns of a tool family.
type ToolManifest struct {
	Family            string                      `json:"family" yaml:"family"`
	Version           string                      `json:"version" yaml:"version"`
	SurfaceKind       string                      `json:"surface_kind" yaml:"surface_kind"`
	LogicalActions    []LogicalAction             `json:"logical_actions" yaml:"logical_actions"`
	SupportedLanes    []accessplane.Lane          `json:"supported_lanes" yaml:"supported_lanes"`
	PreferredLane     map[string]accessplane.Lane `json:"preferred_lane,omitempty" yaml:"preferred_lane,omitempty"`
	AuthPatterns      []string                    `json:"auth_patterns,omitempty" yaml:"auth_patterns,omitempty"`
	Destinations      []Destination               `json:"destinations,omitempty" yaml:"destinations,omitempty"`
	MethodConstraints []MethodConstraint          `json:"method_constraints,omitempty" yaml:"method_constraints,omitempty"`
	ExecutionHints    map[string]string           `json:"execution_hints,omitempty" yaml:"execution_hints,omitempty"`
	ApprovalHints     map[string]string           `json:"approval_hints,omitempty" yaml:"approval_hints,omitempty"`
	HelperSupport     *HelperSupport              `json:"helper_support,omitempty" yaml:"helper_support,omitempty"`
	BinaryMatchers    []string                    `json:"binary_matchers,omitempty" yaml:"binary_matchers,omitempty"`
}

// LogicalAction describes a discrete operation a tool can perform.
type LogicalAction struct {
	Name      string `json:"name" yaml:"name"`
	RiskClass string `json:"risk_class" yaml:"risk_class"`
	Write     bool   `json:"write" yaml:"write"`
}

// Destination describes a remote endpoint a tool communicates with.
type Destination struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
}

// MethodConstraint restricts the HTTP methods and paths a tool may use.
type MethodConstraint struct {
	Method      string `json:"method" yaml:"method"`
	PathPattern string `json:"path_pattern" yaml:"path_pattern"`
}

// HelperSupport describes the credential helper integration for a tool.
type HelperSupport struct {
	Format   string            `json:"format" yaml:"format"`
	Protocol string            `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Env      map[string]string `json:"env,omitempty" yaml:"env,omitempty"`
}
