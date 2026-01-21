// probe_test.go: Tests for probe types and enums
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import "testing"

func TestResourceType_String(t *testing.T) {
	tests := []struct {
		rt       ResourceType
		expected string
	}{
		{ResourceFile, "file"},
		{ResourcePort, "port"},
		{ResourceProcess, "process"},
		{ResourceLog, "log"},
		{ResourceContainer, "container"},
		{ResourceCertificate, "certificate"},
		{ResourceDNS, "dns"},
		{ResourceIAMPolicy, "iam_policy"},
		{ResourceNetworkRule, "network_rule"},
		{ResourceSecret, "secret"},
		{ResourceService, "service"},
		{ResourceEndpoint, "endpoint"},
		{ResourceCustom, "custom"},
		{ResourceType(255), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.rt.String(); got != tc.expected {
			t.Errorf("ResourceType(%d).String() = %q, want %q", tc.rt, got, tc.expected)
		}
	}
}

func TestChangeType_String(t *testing.T) {
	tests := []struct {
		ct       ChangeType
		expected string
	}{
		{ChangeNone, "none"},
		{ChangeCreate, "create"},
		{ChangeModify, "modify"},
		{ChangeDelete, "delete"},
		{ChangeDrift, "drift"},
		{ChangeError, "error"},
		{ChangeType(255), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.ct.String(); got != tc.expected {
			t.Errorf("ChangeType(%d).String() = %q, want %q", tc.ct, got, tc.expected)
		}
	}
}

func TestState_ZeroValue(t *testing.T) {
	var s State
	if s.ResourceID != "" {
		t.Error("zero State should have empty ResourceID")
	}
	if s.Hash != 0 {
		t.Error("zero State should have zero Hash")
	}
	if !s.Timestamp.IsZero() {
		t.Error("zero State should have zero Timestamp")
	}
}

func TestDriftEvent_WithError(t *testing.T) {
	event := DriftEvent{
		ProbeID:    "test",
		ChangeType: ChangeError,
		Error:      ErrProbeFailure,
	}

	if event.ProbeID != "test" {
		t.Error("DriftEvent should preserve ProbeID")
	}
	if event.Error != ErrProbeFailure {
		t.Error("DriftEvent should preserve Error")
	}
	if event.ChangeType != ChangeError {
		t.Error("DriftEvent should have ChangeError type")
	}
}
