package manifest

import (
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

func TestYAMLLoader_ValidManifest(t *testing.T) {
	yamlData := []byte(`
family: test_tool
version: "1.0"
surface_kind: cli
logical_actions:
  - name: read
    risk_class: standard
    write: false
supported_lanes:
  - remote_execution
`)
	loader := &YAMLLoader{}
	m, err := loader.Load(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Family != "test_tool" {
		t.Errorf("expected family test_tool, got %s", m.Family)
	}
	if m.SurfaceKind != "cli" {
		t.Errorf("expected surface_kind cli, got %s", m.SurfaceKind)
	}
	if len(m.SupportedLanes) != 1 || m.SupportedLanes[0] != accessplane.LaneRemoteExecution {
		t.Errorf("unexpected supported_lanes: %v", m.SupportedLanes)
	}
}

func TestYAMLLoader_MissingFamily(t *testing.T) {
	yamlData := []byte(`
version: "1.0"
surface_kind: cli
logical_actions:
  - name: read
    risk_class: standard
    write: false
supported_lanes:
  - remote_execution
`)
	loader := &YAMLLoader{}
	_, err := loader.Load(yamlData)
	if err == nil {
		t.Fatal("expected error for missing family")
	}
}

func TestYAMLLoader_EmptyLanes(t *testing.T) {
	yamlData := []byte(`
family: test_tool
version: "1.0"
surface_kind: cli
logical_actions:
  - name: read
    risk_class: standard
    write: false
supported_lanes: []
`)
	loader := &YAMLLoader{}
	_, err := loader.Load(yamlData)
	if err == nil {
		t.Fatal("expected error for empty supported_lanes")
	}
}

func TestYAMLLoader_NoSupportedLanes(t *testing.T) {
	yamlData := []byte(`
family: test_tool
version: "1.0"
surface_kind: cli
logical_actions:
  - name: read
    risk_class: standard
    write: false
`)
	loader := &YAMLLoader{}
	_, err := loader.Load(yamlData)
	if err == nil {
		t.Fatal("expected error for missing supported_lanes")
	}
}

func TestYAMLLoader_InvalidLane(t *testing.T) {
	yamlData := []byte(`
family: test_tool
version: "1.0"
surface_kind: cli
logical_actions:
  - name: read
    risk_class: standard
    write: false
supported_lanes:
  - bogus_lane
`)
	loader := &YAMLLoader{}
	_, err := loader.Load(yamlData)
	if err == nil {
		t.Fatal("expected error for invalid lane")
	}
}

func TestYAMLLoader_InvalidSurfaceKind(t *testing.T) {
	yamlData := []byte(`
family: test_tool
version: "1.0"
surface_kind: telepathy
logical_actions:
  - name: read
    risk_class: standard
    write: false
supported_lanes:
  - remote_execution
`)
	loader := &YAMLLoader{}
	_, err := loader.Load(yamlData)
	if err == nil {
		t.Fatal("expected error for invalid surface_kind")
	}
}

func TestInMemoryRegistry_RegisterAndGet(t *testing.T) {
	reg := NewInMemoryRegistry()
	m := &ToolManifest{Family: "test"}
	if err := reg.Register(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := reg.Get("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Family != "test" {
		t.Errorf("expected family test, got %s", got.Family)
	}
}

func TestInMemoryRegistry_DuplicateRegister(t *testing.T) {
	reg := NewInMemoryRegistry()
	m := &ToolManifest{Family: "test"}
	_ = reg.Register(m)
	err := reg.Register(m)
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestInMemoryRegistry_GetNotFound(t *testing.T) {
	reg := NewInMemoryRegistry()
	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestInMemoryRegistry_List(t *testing.T) {
	reg := NewInMemoryRegistry()
	_ = reg.Register(&ToolManifest{Family: "a"})
	_ = reg.Register(&ToolManifest{Family: "b"})
	list := reg.List()
	if len(list) != 2 {
		t.Errorf("expected 2 manifests, got %d", len(list))
	}
}
