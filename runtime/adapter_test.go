package runtime

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/bundle"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func loadSchema(t *testing.T, defName string) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile("adapter_schema.json")
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}

	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("unmarshalling schema JSON: %v", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource("adapter_schema.json", inst); err != nil {
		t.Fatalf("adding schema resource: %v", err)
	}

	ref := "adapter_schema.json#/definitions/" + defName
	schema, err := c.Compile(ref)
	if err != nil {
		t.Fatalf("compiling schema %s: %v", ref, err)
	}
	return schema
}

func validInstallPayload() *bundle.ProjectionBundle {
	return &bundle.ProjectionBundle{
		Version:   "v1",
		GrantID:   "grant-001",
		Lane:      accessplane.LaneDirectHTTP,
		ExpiresAt: time.Now().Add(time.Hour),
		AuditMetadata: bundle.AuditMetadata{
			UserID:    "user-1",
			SessionID: "sess-1",
			RunnerID:  "runner-1",
		},
	}
}

func TestSchemaValidatesInstallGrantPayload(t *testing.T) {
	schema := loadSchema(t, "install_grant_request")

	b := validInstallPayload()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err != nil {
		t.Fatalf("schema should accept valid install_grant payload, got: %v", err)
	}
}

func TestSchemaRejectsInstallGrantMissingFields(t *testing.T) {
	schema := loadSchema(t, "install_grant_request")

	malformed := `{"version": "v1"}`
	var v interface{}
	if err := json.Unmarshal([]byte(malformed), &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject install_grant payload missing required fields")
	}
}

func TestSchemaValidatesRevokeGrantPayload(t *testing.T) {
	schema := loadSchema(t, "revoke_grant_request")

	doc := `{"grant_id": "grant-001", "runner_id": "runner-1"}`
	var v interface{}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err != nil {
		t.Fatalf("schema should accept valid revoke_grant payload, got: %v", err)
	}
}

func TestSchemaRejectsRevokeGrantMissingRunnerID(t *testing.T) {
	schema := loadSchema(t, "revoke_grant_request")

	doc := `{"grant_id": "grant-001"}`
	var v interface{}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject revoke_grant payload missing runner_id")
	}
}

func TestSchemaValidatesDescribeGrantStateResponse(t *testing.T) {
	schema := loadSchema(t, "describe_grant_state_response")

	state := GrantState{
		RunnerID:  "runner-1",
		GrantID:   "grant-001",
		Status:    "active",
		Lane:      accessplane.LaneDirectHTTP,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err != nil {
		t.Fatalf("schema should accept valid describe_grant_state response, got: %v", err)
	}
}

func TestSchemaValidatesPublishRunnerEventPayload(t *testing.T) {
	schema := loadSchema(t, "publish_runner_event_request")

	event := RunnerEvent{
		Type:      accessplane.EventRunnerAllocated,
		RunnerID:  "runner-1",
		SessionID: "sess-1",
		Timestamp: time.Now(),
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err != nil {
		t.Fatalf("schema should accept valid runner event payload, got: %v", err)
	}
}

func TestSchemaRejectsPublishRunnerEventMissingType(t *testing.T) {
	schema := loadSchema(t, "publish_runner_event_request")

	doc := `{"runner_id": "r1", "session_id": "s1", "timestamp": "2026-01-01T00:00:00Z"}`
	var v interface{}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject runner event missing type")
	}
}

func TestBundleVersionCompatibility(t *testing.T) {
	schema := loadSchema(t, "install_grant_request")

	b := validInstallPayload()
	b.Version = "v2"
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject bundle with version v2")
	}
}
