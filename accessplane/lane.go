package accessplane

// Lane represents the execution lane for a tool operation.
type Lane string

const (
	LaneDirectHTTP      Lane = "direct_http"
	LaneHelperSession   Lane = "helper_session"
	LaneRemoteExecution Lane = "remote_execution"
)

// ValidLanes is the set of all valid lane values.
var ValidLanes = map[Lane]bool{
	LaneDirectHTTP:      true,
	LaneHelperSession:   true,
	LaneRemoteExecution: true,
}

// ImplementationState tracks whether a lane is actually built yet.
type ImplementationState string

const (
	StateImplemented            ImplementationState = "implemented"
	StateImplementationDeferred ImplementationState = "implementation_deferred"
	StateUnsupportedInPhase1    ImplementationState = "unsupported_in_phase1"
)
