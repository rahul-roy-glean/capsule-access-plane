package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

func loadFixture(t *testing.T, name string) *ToolManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("families", name))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	loader := &YAMLLoader{}
	m, err := loader.Load(data)
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	return m
}

func hasLane(lanes []accessplane.Lane, target accessplane.Lane) bool {
	for _, l := range lanes {
		if l == target {
			return true
		}
	}
	return false
}

func TestGithubRestManifest(t *testing.T) {
	m := loadFixture(t, "github_rest.yaml")
	if m.Family != "github_rest" {
		t.Errorf("expected family github_rest, got %s", m.Family)
	}
	if m.SurfaceKind != "http" {
		t.Errorf("expected surface_kind http, got %s", m.SurfaceKind)
	}
	if !hasLane(m.SupportedLanes, accessplane.LaneDirectHTTP) {
		t.Error("expected direct_http lane")
	}
	if !hasLane(m.SupportedLanes, accessplane.LaneRemoteExecution) {
		t.Error("expected remote_execution lane")
	}
	if len(m.Destinations) == 0 || m.Destinations[0].Host != "api.github.com" {
		t.Error("expected destination api.github.com")
	}
}

func TestGithubGitManifest(t *testing.T) {
	m := loadFixture(t, "github_git.yaml")
	if m.Family != "github_git" {
		t.Errorf("expected family github_git, got %s", m.Family)
	}
	if m.SurfaceKind != "cli" {
		t.Errorf("expected surface_kind cli, got %s", m.SurfaceKind)
	}
	if m.HelperSupport == nil || m.HelperSupport.Format != "credential-helper" {
		t.Error("expected helper_support with format credential-helper")
	}
	if len(m.BinaryMatchers) == 0 || m.BinaryMatchers[0] != "git" {
		t.Error("expected binary_matchers [git]")
	}
}

func TestGCPCliReadManifest(t *testing.T) {
	m := loadFixture(t, "gcp_cli_read.yaml")
	if m.Family != "gcp_cli_read" {
		t.Errorf("expected family gcp_cli_read, got %s", m.Family)
	}
	// All actions should be read-only.
	for _, a := range m.LogicalActions {
		if a.Write {
			t.Errorf("expected read-only actions, got write action %s", a.Name)
		}
	}
	if len(m.BinaryMatchers) != 2 {
		t.Errorf("expected 2 binary_matchers, got %d", len(m.BinaryMatchers))
	}
}

func TestGCPAdcManifest(t *testing.T) {
	m := loadFixture(t, "gcp_adc.yaml")
	if m.Family != "gcp_adc" {
		t.Errorf("expected family gcp_adc, got %s", m.Family)
	}
	if m.SurfaceKind != "sdk" {
		t.Errorf("expected surface_kind sdk, got %s", m.SurfaceKind)
	}
	if m.HelperSupport == nil || m.HelperSupport.Format != "google-executable-source" {
		t.Error("expected helper_support with format google-executable-source")
	}
}

func TestKubectlManifest(t *testing.T) {
	m := loadFixture(t, "kubectl.yaml")
	if m.Family != "kubectl" {
		t.Errorf("expected family kubectl, got %s", m.Family)
	}
	if !hasLane(m.SupportedLanes, accessplane.LaneRemoteExecution) {
		t.Error("expected remote_execution lane")
	}
	if !hasLane(m.SupportedLanes, accessplane.LaneHelperSession) {
		t.Error("expected helper_session lane")
	}
	if m.HelperSupport == nil || m.HelperSupport.Format != "exec-credential" {
		t.Error("expected helper_support with format exec-credential")
	}
}

func TestInternalAdminCliManifest(t *testing.T) {
	m := loadFixture(t, "internal_admin_cli.yaml")
	if m.Family != "internal_admin_cli" {
		t.Errorf("expected family internal_admin_cli, got %s", m.Family)
	}
	// CRITICAL: must have ONLY remote_execution.
	if len(m.SupportedLanes) != 1 {
		t.Fatalf("expected exactly 1 supported lane, got %d", len(m.SupportedLanes))
	}
	if m.SupportedLanes[0] != accessplane.LaneRemoteExecution {
		t.Errorf("expected remote_execution, got %s", m.SupportedLanes[0])
	}
}

func TestAllFixturesLoadAndRegister(t *testing.T) {
	fixtures := []string{
		"github_rest.yaml",
		"github_git.yaml",
		"gcp_cli_read.yaml",
		"gcp_adc.yaml",
		"kubectl.yaml",
		"internal_admin_cli.yaml",
	}
	reg := NewInMemoryRegistry()
	loader := &YAMLLoader{}
	for _, f := range fixtures {
		data, err := os.ReadFile(filepath.Join("families", f))
		if err != nil {
			t.Fatalf("failed to read %s: %v", f, err)
		}
		m, err := loader.Load(data)
		if err != nil {
			t.Fatalf("failed to load %s: %v", f, err)
		}
		if err := reg.Register(m); err != nil {
			t.Fatalf("failed to register %s: %v", f, err)
		}
	}
	if len(reg.List()) != 6 {
		t.Errorf("expected 6 registered manifests, got %d", len(reg.List()))
	}
}
