// ai_metadata.go: Typed metadata for AI resources
//
// Provides structured metadata types for AI-specific resources.
// These enable more precise drift detection and semantic search
// compared to generic map[string]string metadata.
//
// Usage:
//   state := State{
//       ResourceID: "model-llama-3.1",
//       Hash:       computeHash(weights),
//       Metadata:   AIModelMetadata{ModelName: "llama-3.1-8b", ...},
//   }
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

// AIModelMetadata provides structured metadata for AI model resources.
// Use with ResourceModelWeight probe type.
type AIModelMetadata struct {
	// ModelName is the human-readable model identifier
	ModelName string `json:"model_name"`

	// ModelVersion is the semantic version of the model
	ModelVersion string `json:"model_version,omitempty"`

	// Checksum is the cryptographic hash of model weights
	// Format: "algorithm:hexdigest" (e.g., "sha256:abc123...")
	Checksum string `json:"checksum"`

	// ChecksumAlgo is the algorithm used (sha256, blake3, etc.)
	ChecksumAlgo string `json:"checksum_algo"`

	// ParameterCount is the number of parameters (for quick identification)
	ParameterCount int64 `json:"parameter_count,omitempty"`

	// QuantizationType describes quantization (Q4_K_M, FP16, etc.)
	QuantizationType string `json:"quantization_type,omitempty"`

	// Framework is the inference framework (llama.cpp, ONNX, etc.)
	Framework string `json:"framework,omitempty"`

	// Source is where the model was obtained (HuggingFace, internal, etc.)
	Source string `json:"source,omitempty"`

	// ApprovedBy is who approved this model version for use
	ApprovedBy string `json:"approved_by,omitempty"`
}

// PromptTemplateMetadata provides structured metadata for prompt templates.
// Use with ResourcePromptTemplate probe type.
type PromptTemplateMetadata struct {
	// TemplateName is the unique template identifier
	TemplateName string `json:"template_name"`

	// Version is the semantic version of the template
	Version string `json:"version,omitempty"`

	// Checksum is the hash of template content
	Checksum string `json:"checksum"`

	// TokenCount is the approximate token count (for budget planning)
	TokenCount int `json:"token_count,omitempty"`

	// Author is who created/last modified the template
	Author string `json:"author,omitempty"`

	// ApprovedAt is when the template was approved for production
	ApprovedAt string `json:"approved_at,omitempty"`

	// Category classifies the template (system, user, tool, etc.)
	Category string `json:"category,omitempty"`

	// SecurityLevel indicates sensitivity (public, internal, confidential)
	SecurityLevel string `json:"security_level,omitempty"`
}

// AgentConfigMetadata provides structured metadata for agent configurations.
// Use with ResourceAgentConfig probe type.
type AgentConfigMetadata struct {
	// AgentID is the unique agent identifier
	AgentID string `json:"agent_id"`

	// ConfigVersion is the semantic version of the config
	ConfigVersion string `json:"config_version,omitempty"`

	// Checksum is the hash of config content
	Checksum string `json:"checksum"`

	// AllowedPlugins lists plugins this agent can use
	AllowedPlugins []string `json:"allowed_plugins,omitempty"`

	// MaxTokenBudget is the maximum tokens per request
	MaxTokenBudget int `json:"max_token_budget,omitempty"`

	// TrustLevel indicates agent privilege level
	TrustLevel string `json:"trust_level,omitempty"`

	// Owner is the team/user responsible for this agent
	Owner string `json:"owner,omitempty"`

	// LastModifiedBy tracks who last changed the config
	LastModifiedBy string `json:"last_modified_by,omitempty"`
}

// EnvVarMetadata provides structured metadata for environment variables.
// Use with ResourceEnvVar probe type.
type EnvVarMetadata struct {
	// VarName is the environment variable name
	VarName string `json:"var_name"`

	// Checksum is the hash of the value (never store actual secrets)
	Checksum string `json:"checksum"`

	// Category classifies the variable (api_key, config, path, etc.)
	Category string `json:"category,omitempty"`

	// Sensitive indicates if this is a secret value
	Sensitive bool `json:"sensitive,omitempty"`

	// Source tracks where this var comes from (file, vault, k8s, etc.)
	Source string `json:"source,omitempty"`
}
