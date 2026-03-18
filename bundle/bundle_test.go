package bundle

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// validBundle returns a well-formed ProjectionBundle for test use.
func validBundle() *ProjectionBundle {
	return &ProjectionBundle{
		Version:   "v1",
		GrantID:   "grant-001",
		Lane:      accessplane.LaneDirectHTTP,
		ExpiresAt: time.Now().Add(time.Hour),
		AuditMetadata: AuditMetadata{
			UserID:    "user-1",
			SessionID: "sess-1",
			RunnerID:  "runner-1",
		},
	}
}

func TestValidateSuccess(t *testing.T) {
	b := validBundle()
	if err := Validate(b); err != nil {
		t.Fatalf("expected valid bundle, got error: %v", err)
	}
}

func TestValidateMissingVersion(t *testing.T) {
	b := validBundle()
	b.Version = ""
	if err := Validate(b); err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestValidateVersionMismatch(t *testing.T) {
	b := validBundle()
	b.Version = "v2"
	if err := Validate(b); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestValidateMissingGrantID(t *testing.T) {
	b := validBundle()
	b.GrantID = ""
	if err := Validate(b); err == nil {
		t.Fatal("expected error for missing grant_id")
	}
}

func TestValidateMissingLane(t *testing.T) {
	b := validBundle()
	b.Lane = ""
	if err := Validate(b); err == nil {
		t.Fatal("expected error for missing lane")
	}
}

func TestValidateInvalidLane(t *testing.T) {
	b := validBundle()
	b.Lane = "teleport"
	if err := Validate(b); err == nil {
		t.Fatal("expected error for invalid lane")
	}
}

func TestValidateMissingAuditMetadata(t *testing.T) {
	b := validBundle()
	b.AuditMetadata = AuditMetadata{}
	if err := Validate(b); err == nil {
		t.Fatal("expected error for missing audit_metadata fields")
	}
}

func TestValidateTokenInGrantID(t *testing.T) {
	tokens := []string{
		"ghp_abc123",
		"gho_secret",
		"Bearer eyJhbGciOi",
		"ya29.some_google_token",
		"AKIAIOSFODNN7EXAMPLE",
		"xoxb-slack-token",
	}
	for _, tok := range tokens {
		b := validBundle()
		b.GrantID = tok
		if err := Validate(b); err == nil {
			t.Errorf("expected error for token-like grant_id %q", tok)
		}
	}
}

func TestValidateTokenInHelperEnv(t *testing.T) {
	b := validBundle()
	b.HelperConfig = &HelperConfig{
		Format:     "git-credential",
		SocketPath: "/tmp/helper.sock",
		Env: map[string]string{
			"TOKEN": "ghp_leaked_token_value",
		},
	}
	if err := Validate(b); err == nil {
		t.Fatal("expected error for token in helper_config env")
	}
}

func TestValidateTokenInMetadataEmulationHeader(t *testing.T) {
	b := validBundle()
	b.MetadataEmulation = &MetadataEmulationConfig{
		Endpoint: "http://169.254.169.254",
		Headers: map[string]string{
			"Authorization": "Bearer leaked_value",
		},
	}
	if err := Validate(b); err == nil {
		t.Fatal("expected error for token in metadata_emulation header")
	}
}

// --- JSON Schema tests ---

func loadBundleSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile("bundle_schema.json")
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}

	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("unmarshalling schema JSON: %v", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource("bundle_schema.json", inst); err != nil {
		t.Fatalf("adding schema resource: %v", err)
	}

	schema, err := c.Compile("bundle_schema.json")
	if err != nil {
		t.Fatalf("compiling schema: %v", err)
	}
	return schema
}

func TestSchemaValidatesCorrectBundle(t *testing.T) {
	schema := loadBundleSchema(t)

	b := validBundle()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling bundle: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err != nil {
		t.Fatalf("schema should accept valid bundle, got: %v", err)
	}
}

func TestSchemaRejectsMissingRequiredFields(t *testing.T) {
	schema := loadBundleSchema(t)

	malformed := `{"version": "v1"}`
	var v interface{}
	if err := json.Unmarshal([]byte(malformed), &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject bundle missing required fields")
	}
}

func TestSchemaRejectsInvalidVersion(t *testing.T) {
	schema := loadBundleSchema(t)

	b := validBundle()
	b.Version = "v2"
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling bundle: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject version v2")
	}
}

func TestSchemaRejectsInvalidLane(t *testing.T) {
	schema := loadBundleSchema(t)

	doc := `{
		"version": "v1",
		"grant_id": "g1",
		"lane": "teleport",
		"expires_at": "2026-12-31T23:59:59Z",
		"audit_metadata": {"user_id":"u","session_id":"s","runner_id":"r"}
	}`
	var v interface{}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}

	if err := schema.Validate(v); err == nil {
		t.Fatal("schema should reject invalid lane value")
	}
}
