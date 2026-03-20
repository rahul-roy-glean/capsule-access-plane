package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

func TestGetPhantomEnv_AllFamilies(t *testing.T) {
	reg := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, reg); err != nil {
		t.Fatalf("load families: %v", err)
	}

	handler := NewPhantomHandlers(reg)

	req := httptest.NewRequest("GET", "/v1/phantom-env", nil)
	rr := httptest.NewRecorder()
	handler.GetPhantomEnv(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}

	var result map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	// gcp_cli_read has phantom_env configured.
	if result["CLOUDSDK_AUTH_ACCESS_TOKEN"] != "phantom" {
		t.Errorf("CLOUDSDK_AUTH_ACCESS_TOKEN = %q, want phantom", result["CLOUDSDK_AUTH_ACCESS_TOKEN"])
	}
}

func TestGetPhantomEnv_SpecificFamilies(t *testing.T) {
	reg := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, reg); err != nil {
		t.Fatalf("load families: %v", err)
	}

	handler := NewPhantomHandlers(reg)

	req := httptest.NewRequest("GET", "/v1/phantom-env?families=gcp_cli_read", nil)
	rr := httptest.NewRecorder()
	handler.GetPhantomEnv(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	var result map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&result)

	if result["CLOUDSDK_AUTH_ACCESS_TOKEN"] != "phantom" {
		t.Errorf("missing expected phantom env var")
	}
}

func TestGetPhantomEnv_FamilyWithNoPhantom(t *testing.T) {
	reg := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, reg); err != nil {
		t.Fatalf("load families: %v", err)
	}

	handler := NewPhantomHandlers(reg)

	// github_rest has no phantom_env.
	req := httptest.NewRequest("GET", "/v1/phantom-env?families=github_rest", nil)
	rr := httptest.NewRecorder()
	handler.GetPhantomEnv(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	var result map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&result)

	if len(result) != 0 {
		t.Errorf("expected empty result for github_rest, got %v", result)
	}
}
