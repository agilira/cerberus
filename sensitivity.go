// sensitivity.go: Per-resource sensitivity profiles for adaptive polling
//
// Themis Security OS philosophy: Let the policy/user decide how much CPU to pay
// for faster detection. Critical resources (secrets, certs) poll faster than logs.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"sync"
	"time"
)

// MinPollInterval is the absolute minimum polling interval (10ms)
// Below this, CPU overhead becomes excessive
const MinPollInterval = 10 * time.Millisecond

// Sensitivity levels for resources
type Sensitivity uint8

const (
	// SensitivityLow: Non-critical resources, 5s polling (logs, metrics)
	SensitivityLow Sensitivity = iota

	// SensitivityMedium: Standard resources, 1s polling (files, containers)
	SensitivityMedium

	// SensitivityHigh: Important resources, 500ms polling (ports, processes)
	SensitivityHigh

	// SensitivityCritical: Security-critical, 100ms polling (secrets, certs, IAM)
	SensitivityCritical
)

// String returns human-readable sensitivity name
func (s Sensitivity) String() string {
	switch s {
	case SensitivityLow:
		return "low"
	case SensitivityMedium:
		return "medium"
	case SensitivityHigh:
		return "high"
	case SensitivityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// DefaultInterval returns the default polling interval for this sensitivity
func (s Sensitivity) DefaultInterval() time.Duration {
	switch s {
	case SensitivityLow:
		return 5 * time.Second
	case SensitivityMedium:
		return 1 * time.Second
	case SensitivityHigh:
		return 500 * time.Millisecond
	case SensitivityCritical:
		return 100 * time.Millisecond
	default:
		return 1 * time.Second // Unknown defaults to medium
	}
}

// DefaultSensitivityForResource returns the default sensitivity for a resource type
// This embodies security best practices:
// - Secrets, certs, IAM, agent config = Critical (fast detection of compromise)
// - Ports, processes, network, AI resources = High (fast detection of intrusion)
// - Files, containers, services = Medium (balanced)
// - Logs = Low (rarely critical for real-time detection)
func DefaultSensitivityForResource(rt ResourceType) Sensitivity {
	switch rt {
	// Critical: Security-sensitive, breach detection, sovereignty
	case ResourceSecret, ResourceCertificate, ResourceIAMPolicy, ResourceAgentConfig:
		return SensitivityCritical

	// High: Attack surface, intrusion detection, AI tampering
	case ResourcePort, ResourceProcess, ResourceNetworkRule,
		ResourceModelWeight, ResourcePromptTemplate, ResourceEnvVar:
		return SensitivityHigh

	// Medium: Configuration drift, state changes
	case ResourceFile, ResourceContainer, ResourceService, ResourceEndpoint, ResourceDNS, ResourceCustom:
		return SensitivityMedium

	// Low: Observability, not security-critical
	case ResourceLog:
		return SensitivityLow

	// Meta: Cerberus self-health
	case ResourceCerberus:
		return SensitivityMedium

	default:
		return SensitivityMedium
	}
}

// SensitivityProfile configures per-resource polling intervals
// Thread-safe for runtime updates via policy changes
type SensitivityProfile struct {
	mu sync.RWMutex

	// Custom intervals per resource type (overrides sensitivity defaults)
	intervals map[ResourceType]time.Duration

	// Sensitivity per resource type (uses defaults if not set)
	sensitivities map[ResourceType]Sensitivity
}

// NewSensitivityProfile creates a profile with default sensitivities
func NewSensitivityProfile() *SensitivityProfile {
	return &SensitivityProfile{
		intervals:     make(map[ResourceType]time.Duration),
		sensitivities: make(map[ResourceType]Sensitivity),
	}
}

// GetInterval returns the polling interval for a resource type
// Priority: custom interval > sensitivity default > medium default
func (p *SensitivityProfile) GetInterval(rt ResourceType) time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check for custom interval override
	if interval, ok := p.intervals[rt]; ok {
		return p.clampInterval(interval)
	}

	// Check for custom sensitivity
	if sensitivity, ok := p.sensitivities[rt]; ok {
		return sensitivity.DefaultInterval()
	}

	// Use default sensitivity for resource type
	return DefaultSensitivityForResource(rt).DefaultInterval()
}

// SetInterval sets a custom polling interval for a resource type
// Thread-safe for runtime policy updates
func (p *SensitivityProfile) SetInterval(rt ResourceType, interval time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.intervals[rt] = p.clampInterval(interval)
}

// SetSensitivity sets the sensitivity level for a resource type
// Clears any custom interval override
func (p *SensitivityProfile) SetSensitivity(rt ResourceType, s Sensitivity) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sensitivities[rt] = s
	delete(p.intervals, rt) // Clear custom interval
}

// clampInterval ensures interval is within acceptable bounds
func (p *SensitivityProfile) clampInterval(interval time.Duration) time.Duration {
	if interval < MinPollInterval {
		return MinPollInterval
	}
	return interval
}

// Clone returns a deep copy of the profile
func (p *SensitivityProfile) Clone() *SensitivityProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()

	clone := NewSensitivityProfile()
	for k, v := range p.intervals {
		clone.intervals[k] = v
	}
	for k, v := range p.sensitivities {
		clone.sensitivities[k] = v
	}
	return clone
}
