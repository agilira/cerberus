// sensitivity_test.go: Tests for SensitivityProfile and per-resource polling intervals
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"testing"
	"time"
)

// =============================================================================
// SENSITIVITY PROFILE UNIT TESTS
// =============================================================================

func TestSensitivity_String(t *testing.T) {
	tests := []struct {
		s        Sensitivity
		expected string
	}{
		{SensitivityLow, "low"},
		{SensitivityMedium, "medium"},
		{SensitivityHigh, "high"},
		{SensitivityCritical, "critical"},
		{Sensitivity(255), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.s.String(); got != tc.expected {
			t.Errorf("Sensitivity(%d).String() = %q, want %q", tc.s, got, tc.expected)
		}
	}
}

func TestSensitivity_DefaultInterval(t *testing.T) {
	tests := []struct {
		s        Sensitivity
		expected time.Duration
	}{
		{SensitivityLow, 5 * time.Second},
		{SensitivityMedium, 1 * time.Second},
		{SensitivityHigh, 500 * time.Millisecond},
		{SensitivityCritical, 100 * time.Millisecond},
		{Sensitivity(255), 1 * time.Second}, // Unknown defaults to medium
	}

	for _, tc := range tests {
		if got := tc.s.DefaultInterval(); got != tc.expected {
			t.Errorf("Sensitivity(%d).DefaultInterval() = %v, want %v", tc.s, got, tc.expected)
		}
	}
}

func TestDefaultSensitivityForResource(t *testing.T) {
	tests := []struct {
		rt       ResourceType
		expected Sensitivity
	}{
		// Critical resources
		{ResourceSecret, SensitivityCritical},
		{ResourceCertificate, SensitivityCritical},
		{ResourceIAMPolicy, SensitivityCritical},

		// High sensitivity
		{ResourcePort, SensitivityHigh},
		{ResourceProcess, SensitivityHigh},
		{ResourceNetworkRule, SensitivityHigh},

		// Medium sensitivity
		{ResourceFile, SensitivityMedium},
		{ResourceContainer, SensitivityMedium},
		{ResourceService, SensitivityMedium},
		{ResourceEndpoint, SensitivityMedium},
		{ResourceDNS, SensitivityMedium},

		// Low sensitivity
		{ResourceLog, SensitivityLow},

		// Custom defaults to medium
		{ResourceCustom, SensitivityMedium},
	}

	for _, tc := range tests {
		if got := DefaultSensitivityForResource(tc.rt); got != tc.expected {
			t.Errorf("DefaultSensitivityForResource(%s) = %s, want %s", tc.rt, got, tc.expected)
		}
	}
}

func TestSensitivityProfile_GetInterval(t *testing.T) {
	profile := NewSensitivityProfile()

	// Default for Secret should be Critical (100ms)
	interval := profile.GetInterval(ResourceSecret)
	if interval != 100*time.Millisecond {
		t.Errorf("expected Secret interval=100ms, got %v", interval)
	}

	// Default for Log should be Low (5s)
	interval = profile.GetInterval(ResourceLog)
	if interval != 5*time.Second {
		t.Errorf("expected Log interval=5s, got %v", interval)
	}
}

func TestSensitivityProfile_SetInterval(t *testing.T) {
	profile := NewSensitivityProfile()

	// Override Secret to 50ms
	profile.SetInterval(ResourceSecret, 50*time.Millisecond)

	interval := profile.GetInterval(ResourceSecret)
	if interval != 50*time.Millisecond {
		t.Errorf("expected Secret interval=50ms after override, got %v", interval)
	}
}

func TestSensitivityProfile_SetSensitivity(t *testing.T) {
	profile := NewSensitivityProfile()

	// Change File from Medium to Critical
	profile.SetSensitivity(ResourceFile, SensitivityCritical)

	interval := profile.GetInterval(ResourceFile)
	if interval != 100*time.Millisecond {
		t.Errorf("expected File interval=100ms after sensitivity change, got %v", interval)
	}
}

func TestSensitivityProfile_MinInterval(t *testing.T) {
	profile := NewSensitivityProfile()

	// Try to set interval below minimum (10ms)
	profile.SetInterval(ResourceSecret, 1*time.Millisecond)

	interval := profile.GetInterval(ResourceSecret)
	if interval < MinPollInterval {
		t.Errorf("interval should not go below MinPollInterval, got %v", interval)
	}
}

func TestSensitivityProfile_ThreadSafe(t *testing.T) {
	profile := NewSensitivityProfile()

	done := make(chan struct{})

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			profile.SetInterval(ResourceSecret, time.Duration(i)*time.Millisecond+MinPollInterval)
		}
		close(done)
	}()

	// Reader goroutine
	for i := 0; i < 1000; i++ {
		_ = profile.GetInterval(ResourceSecret)
	}

	<-done
}

// =============================================================================
// SENSITIVITY-AWARE POLLING TESTS
// =============================================================================

func TestCerberus_WithSensitivityProfile(t *testing.T) {
	profile := NewSensitivityProfile()
	profile.SetInterval(ResourceSecret, 20*time.Millisecond)
	profile.SetInterval(ResourceLog, 100*time.Millisecond)

	c := New(Config{
		SensitivityProfile: profile,
		BufferSize:         16,
	})

	if c.sensitivityProfile == nil {
		t.Fatal("expected sensitivityProfile to be set")
	}
}

func TestCerberus_DefaultSensitivityProfile(t *testing.T) {
	c := New(Config{})

	if c.sensitivityProfile == nil {
		t.Fatal("expected default sensitivityProfile to be created")
	}

	// Should have default intervals
	interval := c.sensitivityProfile.GetInterval(ResourceSecret)
	if interval != 100*time.Millisecond {
		t.Errorf("expected default Secret interval=100ms, got %v", interval)
	}
}
