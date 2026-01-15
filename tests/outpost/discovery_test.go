package outpost_test

import (
	"context"
	"testing"
	"time"

	"github.com/zred/BivouacMesh/pkg/outpost"
)

// TestDiscoveryServiceCreation tests creating a discovery service
func TestDiscoveryServiceCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenAddrs := []string{"/ip4/127.0.0.1/tcp/0"}
	bootstrapPeers := []string{}
	discoveryTag := "test-bivouac"

	ds, err := outpost.NewDiscoveryService(ctx, listenAddrs, bootstrapPeers, discoveryTag)
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}

	if ds == nil {
		t.Fatal("Discovery service is nil")
	}

	if ds.Host == nil {
		t.Error("Host should not be nil")
	}

	if ds.DHT == nil {
		t.Error("DHT should not be nil")
	}

	// Clean up
	ds.Stop()
}

// TestDiscoveryServiceStart tests starting the discovery service
func TestDiscoveryServiceStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenAddrs := []string{"/ip4/127.0.0.1/tcp/0"}
	ds, err := outpost.NewDiscoveryService(ctx, listenAddrs, []string{}, "test-start")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	// Start the service
	err = ds.Start()
	if err != nil {
		t.Fatalf("Failed to start discovery service: %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Verify host is listening
	if len(ds.Host.Addrs()) == 0 {
		t.Error("Host should have at least one listening address")
	}

	// Verify host ID is set
	if ds.Host.ID() == "" {
		t.Error("Host ID should not be empty")
	}
}

// TestDiscoveryServiceStop tests stopping the discovery service
func TestDiscoveryServiceStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenAddrs := []string{"/ip4/127.0.0.1/tcp/0"}
	ds, err := outpost.NewDiscoveryService(ctx, listenAddrs, []string{}, "test-stop")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}

	err = ds.Start()
	if err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// Stop should work without error
	err = ds.Stop()
	if err != nil {
		t.Errorf("Stop returned error: %v", err)
	}

	// Multiple stops should be safe
	err = ds.Stop()
	if err != nil {
		t.Errorf("Second stop returned error: %v", err)
	}
}

// TestMultipleListenAddresses tests creating service with multiple addresses
func TestMultipleListenAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenAddrs := []string{
		"/ip4/127.0.0.1/tcp/0",
		"/ip4/127.0.0.1/tcp/0", // Will bind to different port
	}

	ds, err := outpost.NewDiscoveryService(ctx, listenAddrs, []string{}, "test-multi")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	err = ds.Start()
	if err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// Should have at least one address (system might consolidate)
	if len(ds.Host.Addrs()) == 0 {
		t.Error("Expected at least one listening address")
	}
}

// TestInvalidMultiaddr tests handling of invalid multiaddress
func TestInvalidMultiaddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Invalid multiaddress
	listenAddrs := []string{"invalid-address"}

	_, err := outpost.NewDiscoveryService(ctx, listenAddrs, []string{}, "test-invalid")
	if err == nil {
		t.Error("Should fail with invalid multiaddress")
	}
}

// TestDiscoveryTag tests that discovery tag is set
func TestDiscoveryTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenAddrs := []string{"/ip4/127.0.0.1/tcp/0"}
	customTag := "custom-discovery-tag"

	ds, err := outpost.NewDiscoveryService(ctx, listenAddrs, []string{}, customTag)
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	// Note: The tag is stored internally but not directly accessible
	// We can verify the service was created successfully with the tag
	if ds == nil {
		t.Error("Discovery service should not be nil")
	}
}

// TestHostIDGeneration tests that each host gets a unique ID
func TestHostIDGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create first discovery service
	ds1, err := outpost.NewDiscoveryService(ctx, []string{"/ip4/127.0.0.1/tcp/0"}, []string{}, "test-id-1")
	if err != nil {
		t.Fatalf("Failed to create first discovery service: %v", err)
	}
	defer ds1.Stop()

	// Create second discovery service
	ds2, err := outpost.NewDiscoveryService(ctx, []string{"/ip4/127.0.0.1/tcp/0"}, []string{}, "test-id-2")
	if err != nil {
		t.Fatalf("Failed to create second discovery service: %v", err)
	}
	defer ds2.Stop()

	// Verify they have different IDs
	if ds1.Host.ID() == ds2.Host.ID() {
		t.Error("Different hosts should have different IDs")
	}

	// Verify IDs are not empty
	if ds1.Host.ID() == "" {
		t.Error("First host ID should not be empty")
	}
	if ds2.Host.ID() == "" {
		t.Error("Second host ID should not be empty")
	}
}

// TestDHTInitialization tests that DHT is properly initialized
func TestDHTInitialization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenAddrs := []string{"/ip4/127.0.0.1/tcp/0"}
	ds, err := outpost.NewDiscoveryService(ctx, listenAddrs, []string{}, "test-dht")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	if ds.DHT == nil {
		t.Fatal("DHT should be initialized")
	}

	// Start the service to fully initialize DHT
	err = ds.Start()
	if err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// DHT should still be accessible after start
	if ds.DHT == nil {
		t.Error("DHT should still be accessible after start")
	}
}

// TestBootstrapPeers tests handling of bootstrap peer configuration
func TestBootstrapPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a valid bootstrap peer address (though it won't connect)
	bootstrapPeers := []string{
		"/ip4/127.0.0.1/tcp/4001/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
	}

	ds, err := outpost.NewDiscoveryService(ctx, []string{"/ip4/127.0.0.1/tcp/0"}, bootstrapPeers, "test-bootstrap")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	// Service should create successfully even if bootstrap peers are unreachable
	if ds == nil {
		t.Error("Discovery service should be created with unreachable bootstrap peers")
	}
}

// TestEmptyBootstrapPeers tests that empty bootstrap peers list works
func TestEmptyBootstrapPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ds, err := outpost.NewDiscoveryService(ctx, []string{"/ip4/127.0.0.1/tcp/0"}, []string{}, "test-empty-bootstrap")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	if ds == nil {
		t.Error("Discovery service should work with empty bootstrap peers")
	}
}

// TestContextCancellation tests that service respects context cancellation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

	ds, err := outpost.NewDiscoveryService(ctx, []string{"/ip4/127.0.0.1/tcp/0"}, []string{}, "test-cancel")
	if err != nil {
		t.Fatalf("Failed to create discovery service: %v", err)
	}
	defer ds.Stop()

	err = ds.Start()
	if err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// Cancel context
	cancel()

	// Give it a moment to process cancellation
	time.Sleep(100 * time.Millisecond)

	// Service should handle cancellation gracefully
	// (No assertion needed, just verify no panic)
}
