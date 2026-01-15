package garrison_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/zred/BivouacMesh/pkg/garrison"
	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// TestConsensusServiceCreation tests creating a consensus service
func TestConsensusServiceCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create identity
	identity, err := perimeter.NewIdentity("consensus-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Create a libp2p host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer host.Close()

	// Create pubsub
	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		t.Fatalf("Failed to create pubsub: %v", err)
	}

	// Create consensus config
	config := garrison.ConsensusConfig{
		Host:      host,
		PubSub:    ps,
		Identity:  identity,
		NatsConn:  nil, // Optional
		JetStream: nil, // Optional
	}

	// Create consensus service
	cs, err := garrison.NewConsensusService(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create consensus service: %v", err)
	}

	if cs == nil {
		t.Fatal("Consensus service is nil")
	}

	// Clean up
	cs.Stop()
}

// TestConsensusServiceStart tests starting the consensus service
func TestConsensusServiceStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("test-consensus")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		t.Fatalf("Failed to create pubsub: %v", err)
	}

	config := garrison.ConsensusConfig{
		Host:     host,
		PubSub:   ps,
		Identity: identity,
	}

	cs, err := garrison.NewConsensusService(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create consensus service: %v", err)
	}
	defer cs.Stop()

	// Start the service
	err = cs.Start()
	if err != nil {
		t.Fatalf("Failed to start consensus service: %v", err)
	}

	// Give it a moment to initialize
	time.Sleep(100 * time.Millisecond)

	// Stop should work cleanly
	cs.Stop()
}

// TestVoteForCapability tests voting for a capability through consensus
func TestVoteForCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("voter-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		t.Fatalf("Failed to create pubsub: %v", err)
	}

	config := garrison.ConsensusConfig{
		Host:     host,
		PubSub:   ps,
		Identity: identity,
	}

	cs, err := garrison.NewConsensusService(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create consensus service: %v", err)
	}
	defer cs.Stop()

	err = cs.Start()
	if err != nil {
		t.Fatalf("Failed to start consensus service: %v", err)
	}

	// Try to vote for a capability (will fail due to missing permission)
	targetKey := make([]byte, 32)
	duration := 24 * time.Hour

	vote, err := cs.VoteForCapability("target-node", targetKey, perimeter.CapabilityRelay, 1, duration)

	// We expect an error because this node doesn't have the required capability to vote
	if err == nil {
		t.Error("Expected error when voting without required capability")
	}

	// Vote should be nil when error occurs
	if vote != nil && err != nil {
		t.Error("Vote should be nil when error occurs")
	}
}

// TestHasCapability tests checking if a node has a capability
func TestHasCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("check-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		t.Fatalf("Failed to create pubsub: %v", err)
	}

	config := garrison.ConsensusConfig{
		Host:     host,
		PubSub:   ps,
		Identity: identity,
	}

	cs, err := garrison.NewConsensusService(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create consensus service: %v", err)
	}
	defer cs.Stop()

	// Check for non-existent capability
	hasCapability, level := cs.HasCapability("some-node", perimeter.CapabilityCA)
	if hasCapability {
		t.Error("Node should not have capability initially")
	}
	if level != 0 {
		t.Errorf("Expected level 0, got %d", level)
	}
}

// TestGetNodeCapabilities tests retrieving capabilities
func TestGetNodeCapabilities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("cap-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		t.Fatalf("Failed to create pubsub: %v", err)
	}

	config := garrison.ConsensusConfig{
		Host:     host,
		PubSub:   ps,
		Identity: identity,
	}

	cs, err := garrison.NewConsensusService(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create consensus service: %v", err)
	}
	defer cs.Stop()

	// Get capabilities for a node (should be empty)
	caps := cs.GetNodeCapabilities("test-node")
	if caps == nil {
		t.Error("GetNodeCapabilities should return empty slice, not nil")
	}
	if len(caps) != 0 {
		t.Errorf("Expected 0 capabilities, got %d", len(caps))
	}
}

// TestConsensusServiceStop tests stopping the service
func TestConsensusServiceStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("stop-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		t.Fatalf("Failed to create pubsub: %v", err)
	}

	config := garrison.ConsensusConfig{
		Host:     host,
		PubSub:   ps,
		Identity: identity,
	}

	cs, err := garrison.NewConsensusService(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create consensus service: %v", err)
	}

	err = cs.Start()
	if err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// Stop should work multiple times without error
	cs.Stop()
	cs.Stop() // Second stop should be safe
}

// TestConsensusConfigValidation tests that config validation works
func TestConsensusConfigValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test with invalid config (missing required fields)
	invalidConfig := garrison.ConsensusConfig{
		Host:     nil, // Invalid
		PubSub:   nil,
		Identity: nil,
	}

	_, err := garrison.NewConsensusService(ctx, invalidConfig)
	if err == nil {
		t.Error("Should fail with invalid config")
	}
}
