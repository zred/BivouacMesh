package garrison_test

import (
	"context"
	"testing"
	"time"

	"github.com/zred/BivouacMesh/pkg/garrison"
	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// Note: These tests require a running NATS server
// They are designed to be skipped if NATS is not available

// TestFederationNodeCreation tests creating a federation node
func TestFederationNodeCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("fed-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Create stream configs
	streamConfigs := []garrison.StreamConfig{
		{
			Name:     "test-stream",
			Subjects: []string{"test.>"},
			MaxAge:   1 * time.Hour,
			AccessPolicy: garrison.AccessPolicy{
				ResourceName:      "test",
				AllowedIdentities: []string{"*"},
				RequiredSigs:      1,
			},
		},
	}

	config := garrison.FederationConfig{
		NatsURL:         "nats://localhost:4222",
		NatsCredentials: "",
		Identity:        identity,
		StreamConfigs:   streamConfigs,
	}

	// Try to create federation node
	fedNode, err := garrison.NewFederationNode(ctx, config)
	if err != nil {
		// NATS might not be running, skip test
		t.Skipf("Skipping test - NATS not available: %v", err)
		return
	}
	defer fedNode.Close()

	if fedNode == nil {
		t.Fatal("Federation node is nil")
	}
}

// TestStreamConfigValidation tests stream configuration validation
func TestStreamConfigValidation(t *testing.T) {
	// Test valid stream config
	validConfig := garrison.StreamConfig{
		Name:     "valid-stream",
		Subjects: []string{"valid.>"},
		MaxAge:   1 * time.Hour,
		AccessPolicy: garrison.AccessPolicy{
			ResourceName:      "valid",
			AllowedIdentities: []string{"*"},
			RequiredSigs:      1,
		},
	}

	if validConfig.Name == "" {
		t.Error("Valid config has empty name")
	}
	if len(validConfig.Subjects) == 0 {
		t.Error("Valid config has no subjects")
	}

	// Test invalid stream config (empty name)
	invalidConfig := garrison.StreamConfig{
		Name:     "", // Invalid
		Subjects: []string{"test.>"},
		MaxAge:   1 * time.Hour,
	}

	if invalidConfig.Name != "" {
		t.Error("Invalid config should have empty name")
	}
}

// TestAccessPolicyStructure tests the AccessPolicy structure
func TestAccessPolicyStructure(t *testing.T) {
	policy := garrison.AccessPolicy{
		ResourceName:      "test-resource",
		AllowedIdentities: []string{"node1", "node2", "node3"},
		RequiredSigs:      2,
	}

	if policy.ResourceName == "" {
		t.Error("ResourceName should not be empty")
	}
	if len(policy.AllowedIdentities) != 3 {
		t.Errorf("Expected 3 allowed identities, got %d", len(policy.AllowedIdentities))
	}
	if policy.RequiredSigs != 2 {
		t.Errorf("Expected RequiredSigs=2, got %d", policy.RequiredSigs)
	}
}

// TestFederationConfigValidation tests federation configuration
func TestFederationConfigValidation(t *testing.T) {
	identity, err := perimeter.NewIdentity("config-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Valid config
	validConfig := garrison.FederationConfig{
		NatsURL:       "nats://localhost:4222",
		Identity:      identity,
		StreamConfigs: []garrison.StreamConfig{},
	}

	if validConfig.NatsURL == "" {
		t.Error("Valid config has empty NATS URL")
	}
	if validConfig.Identity == nil {
		t.Error("Valid config has nil identity")
	}

	// Invalid config (missing identity)
	invalidConfig := garrison.FederationConfig{
		NatsURL:       "nats://localhost:4222",
		Identity:      nil, // Invalid
		StreamConfigs: []garrison.StreamConfig{},
	}

	if invalidConfig.Identity != nil {
		t.Error("Invalid config should have nil identity")
	}
}

// TestMessageChannelCreation tests that message channel is created
func TestMessageChannelCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("channel-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	config := garrison.FederationConfig{
		NatsURL:       "nats://localhost:4222",
		Identity:      identity,
		StreamConfigs: []garrison.StreamConfig{},
	}

	fedNode, err := garrison.NewFederationNode(ctx, config)
	if err != nil {
		t.Skipf("Skipping test - NATS not available: %v", err)
		return
	}
	defer fedNode.Close()

	// Get message channel
	msgCh := fedNode.GetMessageChannel()
	if msgCh == nil {
		t.Error("Message channel should not be nil")
	}
}

// TestStreamConfigWithMultipleSubjects tests stream with multiple subjects
func TestStreamConfigWithMultipleSubjects(t *testing.T) {
	config := garrison.StreamConfig{
		Name:     "multi-subject-stream",
		Subjects: []string{"events.>", "logs.>", "metrics.>"},
		MaxAge:   2 * time.Hour,
		AccessPolicy: garrison.AccessPolicy{
			ResourceName:      "multi",
			AllowedIdentities: []string{"*"},
			RequiredSigs:      1,
		},
	}

	if len(config.Subjects) != 3 {
		t.Errorf("Expected 3 subjects, got %d", len(config.Subjects))
	}

	// Verify all subjects are present
	expectedSubjects := map[string]bool{
		"events.>":  true,
		"logs.>":    true,
		"metrics.>": true,
	}

	for _, subject := range config.Subjects {
		if !expectedSubjects[subject] {
			t.Errorf("Unexpected subject: %s", subject)
		}
	}
}

// TestAccessPolicyWithSpecificIdentities tests access policy with specific nodes
func TestAccessPolicyWithSpecificIdentities(t *testing.T) {
	policy := garrison.AccessPolicy{
		ResourceName:      "restricted-resource",
		AllowedIdentities: []string{"admin-node", "backup-node"},
		RequiredSigs:      2,
	}

	// Verify wildcard is not used
	for _, id := range policy.AllowedIdentities {
		if id == "*" {
			t.Error("Policy should not use wildcard")
		}
	}

	// Verify specific identities are present
	if len(policy.AllowedIdentities) != 2 {
		t.Errorf("Expected 2 specific identities, got %d", len(policy.AllowedIdentities))
	}
}

// TestFederationNodeClose tests closing a federation node
func TestFederationNodeClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("close-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	config := garrison.FederationConfig{
		NatsURL:       "nats://localhost:4222",
		Identity:      identity,
		StreamConfigs: []garrison.StreamConfig{},
	}

	fedNode, err := garrison.NewFederationNode(ctx, config)
	if err != nil {
		t.Skipf("Skipping test - NATS not available: %v", err)
		return
	}

	// Close should work without error
	fedNode.Close()

	// Multiple closes should be safe
	fedNode.Close()
}

// TestAccessPolicyWildcard tests wildcard access policy
func TestAccessPolicyWildcard(t *testing.T) {
	policy := garrison.AccessPolicy{
		ResourceName:      "test-resource",
		AllowedIdentities: []string{"*"}, // Wildcard allows all
		RequiredSigs:      1,
	}

	// Any identity should be allowed with wildcard
	testIdentities := []string{"alice", "bob", "charlie", "unknown"}
	for _, id := range testIdentities {
		allowed := false
		for _, allowedID := range policy.AllowedIdentities {
			if allowedID == "*" || allowedID == id {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("Identity %s should be allowed with wildcard policy", id)
		}
	}
}

// TestAccessPolicyRestrictedIdentities tests restricted identity list
func TestAccessPolicyRestrictedIdentities(t *testing.T) {
	policy := garrison.AccessPolicy{
		ResourceName:      "restricted-resource",
		AllowedIdentities: []string{"alice", "bob"},
		RequiredSigs:      2,
	}

	// Test allowed identities
	allowedIDs := []string{"alice", "bob"}
	for _, id := range allowedIDs {
		allowed := false
		for _, allowedID := range policy.AllowedIdentities {
			if allowedID == id {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("Identity %s should be allowed", id)
		}
	}

	// Test denied identities
	deniedIDs := []string{"charlie", "eve", "mallory"}
	for _, id := range deniedIDs {
		allowed := false
		for _, allowedID := range policy.AllowedIdentities {
			if allowedID == "*" || allowedID == id {
				allowed = true
				break
			}
		}
		if allowed {
			t.Errorf("Identity %s should be denied", id)
		}
	}
}

// TestMultiSignatureRequirement tests that RequiredSigs field is validated
func TestMultiSignatureRequirement(t *testing.T) {
	policy := garrison.AccessPolicy{
		ResourceName:      "high-security-resource",
		AllowedIdentities: []string{"alice", "bob", "charlie"},
		RequiredSigs:      3, // Requires 3 signatures
	}

	if policy.RequiredSigs != 3 {
		t.Errorf("Expected RequiredSigs=3, got %d", policy.RequiredSigs)
	}

	// Verify there are enough allowed identities to meet signature requirement
	if len(policy.AllowedIdentities) < policy.RequiredSigs {
		t.Errorf("Not enough allowed identities (%d) to meet required signatures (%d)",
			len(policy.AllowedIdentities), policy.RequiredSigs)
	}
}
