package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address                  string
	PublicURL                string
	DatabaseURL              string
	CapsuleControlPlaneURL   string
	CapsuleControlPlaneToken string
	AttestationSecret        string
	DefaultGrantTTL          time.Duration
	ExecutionMaxRuntime      time.Duration
	ExecutionMaxOutputBytes  int64
	AllowedCLITools          []string
}

func Load() (Config, error) {
	cfg := Config{
		Address:                  getenv("ACCESS_PLANE_ADDR", ":8090"),
		PublicURL:                strings.TrimRight(getenv("ACCESS_PLANE_PUBLIC_URL", "http://localhost:8090"), "/"),
		DatabaseURL:              getenv("ACCESS_PLANE_DATABASE_URL", "file:access-plane.db?_pragma=foreign_keys(1)"),
		CapsuleControlPlaneURL:   strings.TrimRight(os.Getenv("CAPSULE_CONTROL_PLANE_URL"), "/"),
		CapsuleControlPlaneToken: os.Getenv("CAPSULE_CONTROL_PLANE_TOKEN"),
		AttestationSecret:        os.Getenv("ACCESS_PLANE_ATTESTATION_SECRET"),
		DefaultGrantTTL:          durationEnv("ACCESS_PLANE_DEFAULT_GRANT_TTL", 10*time.Minute),
		ExecutionMaxRuntime:      durationEnv("ACCESS_PLANE_EXECUTION_MAX_RUNTIME", 5*time.Minute),
		ExecutionMaxOutputBytes:  int64Env("ACCESS_PLANE_EXECUTION_MAX_OUTPUT_BYTES", 512*1024),
		AllowedCLITools:          csvEnv("ACCESS_PLANE_ALLOWED_CLI_TOOLS", []string{"gh", "kubectl", "gcloud"}),
	}
	if cfg.AttestationSecret == "" {
		return Config{}, fmt.Errorf("ACCESS_PLANE_ATTESTATION_SECRET is required")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func int64Env(key string, fallback int64) int64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return parsed
		}
	}
	return fallback
}

func csvEnv(key string, fallback []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}
