package identity

import "testing"

func TestEffectiveIdentity_UserDirect(t *testing.T) {
	c := &Claims{
		RunnerID:     "r1",
		IdentityMode: "user-direct",
		UserEmail:    "alice@example.com",
	}
	if got := c.EffectiveIdentity(); got != "alice@example.com" {
		t.Errorf("EffectiveIdentity() = %q, want alice@example.com", got)
	}
}

func TestEffectiveIdentity_Virtual(t *testing.T) {
	c := &Claims{
		RunnerID:          "r1",
		IdentityMode:      "virtual",
		VirtualIdentityID: "agent-nightly-monitor",
	}
	if got := c.EffectiveIdentity(); got != "agent-nightly-monitor" {
		t.Errorf("EffectiveIdentity() = %q, want agent-nightly-monitor", got)
	}
}

func TestEffectiveIdentity_Default(t *testing.T) {
	c := &Claims{RunnerID: "r1"}
	if got := c.EffectiveIdentity(); got != "r1" {
		t.Errorf("EffectiveIdentity() = %q, want r1", got)
	}
}

func TestEffectiveIdentity_UserDirectNoEmail(t *testing.T) {
	c := &Claims{
		RunnerID:     "r1",
		IdentityMode: "user-direct",
	}
	// No email set — falls through to RunnerID.
	if got := c.EffectiveIdentity(); got != "r1" {
		t.Errorf("EffectiveIdentity() = %q, want r1", got)
	}
}
