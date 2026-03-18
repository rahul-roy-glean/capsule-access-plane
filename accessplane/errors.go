package accessplane

import (
	"encoding/json"
	"fmt"
)

// DeniedError is returned when policy denies an operation.
type DeniedError struct {
	Lane   Lane   `json:"lane,omitempty"`
	Family string `json:"family"`
	Reason string `json:"reason"`
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("denied: family=%s reason=%s", e.Family, e.Reason)
}

func (e *DeniedError) MarshalJSON() ([]byte, error) {
	type alias DeniedError
	return json.Marshal(&struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  "denied",
		alias: (*alias)(e),
	})
}

// DeferredError is returned when the correct lane is identified but not implemented yet.
type DeferredError struct {
	Lane   Lane   `json:"lane"`
	Family string `json:"family"`
	Reason string `json:"reason"`
}

func (e *DeferredError) Error() string {
	return fmt.Sprintf("deferred: family=%s lane=%s reason=%s", e.Family, e.Lane, e.Reason)
}

func (e *DeferredError) MarshalJSON() ([]byte, error) {
	type alias DeferredError
	return json.Marshal(&struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  "deferred",
		alias: (*alias)(e),
	})
}

// UnsupportedError is returned when an operation is not supported in the current phase.
type UnsupportedError struct {
	Lane   Lane   `json:"lane,omitempty"`
	Family string `json:"family"`
	Reason string `json:"reason"`
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("unsupported: family=%s reason=%s", e.Family, e.Reason)
}

func (e *UnsupportedError) MarshalJSON() ([]byte, error) {
	type alias UnsupportedError
	return json.Marshal(&struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  "unsupported",
		alias: (*alias)(e),
	})
}
