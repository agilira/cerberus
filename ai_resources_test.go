// ai_resources_test.go: TDD tests for AI-specific resource types
//
// Themis as Sovereign Agentic OS needs to monitor AI-specific resources:
// - Model weights (LLM tampering)
// - Prompt templates (prompt injection persistence)
// - Environment variables (agent hijacking)
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"testing"
)

// =============================================================================
// AI RESOURCE TYPE TESTS
// =============================================================================

func TestResourceType_ModelWeight(t *testing.T) {
	rt := ResourceModelWeight
	if rt.String() != "model_weight" {
		t.Errorf("expected model_weight, got %s", rt.String())
	}
}

func TestResourceType_PromptTemplate(t *testing.T) {
	rt := ResourcePromptTemplate
	if rt.String() != "prompt_template" {
		t.Errorf("expected prompt_template, got %s", rt.String())
	}
}

func TestResourceType_EnvVar(t *testing.T) {
	rt := ResourceEnvVar
	if rt.String() != "env_var" {
		t.Errorf("expected env_var, got %s", rt.String())
	}
}

func TestResourceType_AgentConfig(t *testing.T) {
	rt := ResourceAgentConfig
	if rt.String() != "agent_config" {
		t.Errorf("expected agent_config, got %s", rt.String())
	}
}

func TestDefaultSensitivity_AIResources(t *testing.T) {
	// AI resources should have appropriate default sensitivity
	tests := []struct {
		resource       ResourceType
		minSensitivity Sensitivity
	}{
		{ResourceModelWeight, SensitivityHigh},     // Model tampering = serious
		{ResourcePromptTemplate, SensitivityHigh},  // Prompt injection = serious
		{ResourceEnvVar, SensitivityHigh},          // Env hijacking = serious
		{ResourceAgentConfig, SensitivityCritical}, // Agent config = critical
	}

	for _, tt := range tests {
		t.Run(tt.resource.String(), func(t *testing.T) {
			got := DefaultSensitivityForResource(tt.resource)
			if got < tt.minSensitivity {
				t.Errorf("expected sensitivity >= %v for %s, got %v",
					tt.minSensitivity, tt.resource, got)
			}
		})
	}
}

func TestResourceType_AllAITypesExist(t *testing.T) {
	// Verify all AI resource types are defined
	aiTypes := []ResourceType{
		ResourceModelWeight,
		ResourcePromptTemplate,
		ResourceEnvVar,
		ResourceAgentConfig,
		ResourceCerberus, // Meta-resource for self-health
	}

	for _, rt := range aiTypes {
		if rt.String() == "unknown" {
			t.Errorf("AI resource type %d returned 'unknown'", rt)
		}
	}
}

func TestEntityTypeToResourceType_AITypes(t *testing.T) {
	// Verify entity type mapping includes AI types
	tests := []struct {
		entityType string
		expected   ResourceType
	}{
		{"model_weight", ResourceModelWeight},
		{"prompt_template", ResourcePromptTemplate},
		{"env_var", ResourceEnvVar},
		{"environment_variable", ResourceEnvVar},
		{"agent_config", ResourceAgentConfig},
	}

	for _, tt := range tests {
		t.Run(tt.entityType, func(t *testing.T) {
			// This test is for the orchestrator's EntityTypeToResourceType
			// We just verify the constants exist here
			_ = tt.expected.String()
		})
	}
}

// =============================================================================
// AI METADATA TYPED TESTS (C. Typed Metadata for semantic drift detection)
// =============================================================================

func TestAIModelMetadata_Fields(t *testing.T) {
	meta := AIModelMetadata{
		ModelName:        "llama-3.1-8b",
		ModelVersion:     "1.0.0",
		Checksum:         "sha256:abc123...",
		ChecksumAlgo:     "sha256",
		ParameterCount:   8_000_000_000,
		QuantizationType: "Q4_K_M",
		Framework:        "llama.cpp",
	}

	if meta.ModelName != "llama-3.1-8b" {
		t.Errorf("unexpected ModelName: %s", meta.ModelName)
	}
	if meta.ModelVersion != "1.0.0" {
		t.Errorf("unexpected ModelVersion: %s", meta.ModelVersion)
	}
	if meta.Checksum != "sha256:abc123..." {
		t.Errorf("unexpected Checksum: %s", meta.Checksum)
	}
	if meta.ChecksumAlgo != "sha256" {
		t.Errorf("unexpected ChecksumAlgo: %s", meta.ChecksumAlgo)
	}
	if meta.ParameterCount != 8_000_000_000 {
		t.Errorf("unexpected ParameterCount: %d", meta.ParameterCount)
	}
	if meta.QuantizationType != "Q4_K_M" {
		t.Errorf("unexpected QuantizationType: %s", meta.QuantizationType)
	}
	if meta.Framework != "llama.cpp" {
		t.Errorf("unexpected Framework: %s", meta.Framework)
	}
}

func TestPromptTemplateMetadata_Fields(t *testing.T) {
	meta := PromptTemplateMetadata{
		TemplateName: "system-security",
		Version:      "2.1.0",
		Checksum:     "sha256:def456...",
		TokenCount:   1500,
		Author:       "security-team",
		ApprovedAt:   "2025-01-06T12:00:00Z",
	}

	if meta.TemplateName != "system-security" {
		t.Errorf("unexpected TemplateName: %s", meta.TemplateName)
	}
	if meta.Version != "2.1.0" {
		t.Errorf("unexpected Version: %s", meta.Version)
	}
	if meta.Checksum != "sha256:def456..." {
		t.Errorf("unexpected Checksum: %s", meta.Checksum)
	}
	if meta.TokenCount != 1500 {
		t.Errorf("unexpected TokenCount: %d", meta.TokenCount)
	}
	if meta.Author != "security-team" {
		t.Errorf("unexpected Author: %s", meta.Author)
	}
	if meta.ApprovedAt != "2025-01-06T12:00:00Z" {
		t.Errorf("unexpected ApprovedAt: %s", meta.ApprovedAt)
	}
}

func TestAgentConfigMetadata_Fields(t *testing.T) {
	meta := AgentConfigMetadata{
		AgentID:        "themis-orchestrator",
		ConfigVersion:  "1.5.0",
		Checksum:       "sha256:ghi789...",
		AllowedPlugins: []string{"file_ops", "network"},
		MaxTokenBudget: 100000,
		TrustLevel:     "high",
	}

	if meta.AgentID != "themis-orchestrator" {
		t.Errorf("unexpected AgentID: %s", meta.AgentID)
	}
	if meta.ConfigVersion != "1.5.0" {
		t.Errorf("unexpected ConfigVersion: %s", meta.ConfigVersion)
	}
	if meta.Checksum != "sha256:ghi789..." {
		t.Errorf("unexpected Checksum: %s", meta.Checksum)
	}
	if len(meta.AllowedPlugins) != 2 {
		t.Errorf("unexpected AllowedPlugins count: %d", len(meta.AllowedPlugins))
	}
	if meta.MaxTokenBudget != 100000 {
		t.Errorf("unexpected MaxTokenBudget: %d", meta.MaxTokenBudget)
	}
	if meta.TrustLevel != "high" {
		t.Errorf("unexpected TrustLevel: %s", meta.TrustLevel)
	}
}
