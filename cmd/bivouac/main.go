package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/zred/BivouacMesh/pkg/garrison"
	"github.com/zred/BivouacMesh/pkg/outpost"
	"github.com/zred/BivouacMesh/pkg/perimeter"
	"github.com/zred/BivouacMesh/pkg/signals"
	"github.com/zred/BivouacMesh/pkg/scouts"
)

func main() {
	// Parse command line flags
	var (
		nodeName       = flag.String("name", "bivouac-node", "Node name")
		listenAddrs    = flag.String("listen", "/ip4/0.0.0.0/tcp/9000", "Comma-separated list of addresses to listen on")
		bootstrapPeers = flag.String("bootstrap", "", "Comma-separated list of bootstrap peers")
		natsURL        = flag.String("nats", "nats://localhost:4222", "NATS server URL")
		federationMode = flag.Bool("federation", false, "Run as a federation node")
		ipfsAPI        = flag.String("ipfs", "localhost:5001", "IPFS API endpoint")
		isRootCA       = flag.Bool("root-ca", false, "Run as a root CA")
		
		// New consensus-related flags
		enableConsensus = flag.Bool("consensus", true, "Enable capability consensus")
		bootstrapCapabilities = flag.String("bootstrap-cap", "", "Bootstrap capabilities for this node (comma-separated, e.g. 'ca,federation')")
	)
	flag.Parse()

	fmt.Println("Starting Bivouac Mesh node:", *nodeName)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Create identity
	identity, err := perimeter.NewIdentity(*nodeName)
	if err != nil {
		fmt.Printf("Failed to create identity: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Identity created:", identity.Cert.Subject.CommonName)

	// Parse listen addresses
	addrList := strings.Split(*listenAddrs, ",")
	
	// Parse bootstrap peers
	var peerList []string
	if *bootstrapPeers != "" {
		peerList = strings.Split(*bootstrapPeers, ",")
	}

	// Create discovery service
	discovery, err := outpost.NewDiscoveryService(ctx, addrList, peerList, "bivouac-mesh")
	if err != nil {
		fmt.Printf("Failed to create discovery service: %v\n", err)
		os.Exit(1)
	}

	// Start discovery service
	if err := discovery.Start(); err != nil {
		fmt.Printf("Failed to start discovery service: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Discovery service started. Node address:")
	for _, addr := range discovery.Host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr.String(), discovery.Host.ID().String())
	}

	// Create pubsub for gossip and consensus
	ps, err := pubsub.NewGossipSub(ctx, discovery.Host)
	if err != nil {
		fmt.Printf("Failed to create pubsub: %v\n", err)
		os.Exit(1)
	}

	// Initialize distributed PKI if IPFS is available
	var dpki *perimeter.DistributedPKI
	if *ipfsAPI != "" {
		// Configure the PKI
		pkiConfig := perimeter.PKIConfig{
			Host:         discovery.Host,
			IPFSEndpoint: *ipfsAPI,
			NatsURL:      *natsURL,
			Identity:     identity,
			IsRootCA:     *isRootCA,
		}
		
		// Create the PKI
		dpki, err = perimeter.NewDistributedPKI(ctx, pkiConfig)
		if err != nil {
			fmt.Printf("Warning: Failed to initialize PKI: %v\n", err)
		} else {
			fmt.Println("Distributed PKI initialized successfully")
		}
	}

	// Set up federation node if requested
	var fedNode *garrison.FederationNode
	if *federationMode {
		fmt.Println("Starting in federation mode with NATS:", *natsURL)
		
		// Setup federation node
		streamConfigs := []garrison.StreamConfig{
			{
				Name:     "global",
				Subjects: []string{"bivouac.global.>"},
				MaxAge:   24 * time.Hour,
				AccessPolicy: garrison.AccessPolicy{
					ResourceName:     "global",
					AllowedIdentities: []string{"*"}, // Allow all identities for demo
					RequiredSigs:     1,
				},
			},
			{
				Name:     "private",
				Subjects: []string{"bivouac.private.>"},
				MaxAge:   24 * time.Hour,
				AccessPolicy: garrison.AccessPolicy{
					ResourceName:     "private",
					AllowedIdentities: []string{identity.Cert.Subject.CommonName}, // Only allow this node
					RequiredSigs:     1,
				},
			},
		}
		
		fedConfig := garrison.FederationConfig{
			NatsURL:         *natsURL,
			NatsCredentials: "", // No credentials for demo
			Identity:        identity,
			StreamConfigs:   streamConfigs,
		}
		
		fedNode, err = garrison.NewFederationNode(ctx, fedConfig)
		if err != nil {
			fmt.Printf("Failed to create federation node: %v\n", err)
			os.Exit(1)
		}
		
		// Subscribe to streams
		if err := fedNode.SubscribeToStream("global", "global-consumer"); err != nil {
			fmt.Printf("Failed to subscribe to global stream: %v\n", err)
			os.Exit(1)
		}
		
		if err := fedNode.SubscribeToStream("private", "private-consumer"); err != nil {
			fmt.Printf("Failed to subscribe to private stream: %v\n", err)
			os.Exit(1)
		}
		
		// Process messages from federation
		go func() {
			msgCh := fedNode.GetMessageChannel()
			for msg := range msgCh {
				fmt.Printf("Received message from %s: %s\n", msg.Sender, msg.Payload)
			}
		}()
	}

	// Set up capability consensus if enabled
	var consensusService *garrison.ConsensusService
	if *enableConsensus {
		// Configure consensus service
		consensusConfig := garrison.ConsensusConfig{
			Host:      discovery.Host,
			PubSub:    ps,
			Identity:  identity,
			NatsConn:  nil, // Will be set if federation mode is enabled
			JetStream: nil,
		}
		
		// If federation mode is enabled, use NATS for consensus
		if *federationMode && fedNode != nil {
			consensusConfig.NatsConn = fedNode.NatsConn
			consensusConfig.JetStream = fedNode.JetStream
		}
		
		// Create consensus service
		consensusService, err = garrison.NewConsensusService(ctx, consensusConfig)
		if err != nil {
			fmt.Printf("Failed to create consensus service: %v\n", err)
			os.Exit(1)
		}
		
		// Start consensus service
		if err := consensusService.Start(); err != nil {
			fmt.Printf("Failed to start consensus service: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println("Capability consensus service started")
		
		// If bootstrap capabilities were specified, use them
		if *bootstrapCapabilities != "" {
			capList := strings.Split(*bootstrapCapabilities, ",")
			for _, capStr := range capList {
				capStr = strings.TrimSpace(capStr)
				capType := perimeter.CapabilityType(capStr)
				
				// Is this a recognized capability type?
				if _, ok := perimeter.DefaultCapabilityRequirements[capType]; !ok {
					fmt.Printf("Warning: Unknown capability type '%s'\n", capType)
					continue
				}
				
				fmt.Printf("Requesting capability: %s\n", capType)
				// This would normally involve a more complex process with voting,
				// but for bootstrapping, we'll need some mechanism to grant initial capabilities
				
				// In a real implementation, this might connect to existing nodes and request votes
				// For now, we'll just print a message
				fmt.Printf("Please connect more nodes and vote for this node to receive the %s capability\n", capType)
			}
		}
	}
	
	// Create secure channel for demonstration
	secureChannel, err := signals.NewSecureChannel()
	if err != nil {
		fmt.Printf("Failed to create secure channel: %v\n", err)
		os.Exit(1)
	}
	
	// Create message filter for demonstration
	msgFilter := scouts.NewMessageFilter(10000, 0.01)
	
	// Demo message processing
	sampleMessage := []byte("Hello, Bivouac Mesh!")
	msgID := []byte("msg-1234")
	
	if !msgFilter.HasSeen(msgID) {
		msgFilter.MarkSeen(msgID)
		fmt.Println("Processing new message:", string(sampleMessage))
		
		// Encrypt message (would normally be sent to a peer)
		encrypted, err := secureChannel.Encrypt(sampleMessage)
		if err != nil {
			fmt.Printf("Failed to encrypt message: %v\n", err)
		} else {
			fmt.Printf("Encrypted message (len=%d): %x...\n", len(encrypted), encrypted[:16])
		}
	} else {
		fmt.Println("Duplicate message detected, ignoring")
	}
	
	// Create a simple Merkle tree for demonstration
	dataBlocks := [][]byte{
		[]byte("Block 1"),
		[]byte("Block 2"),
		[]byte("Block 3"),
	}
	
	merkleTree, err := scouts.NewMerkleTree(dataBlocks)
	if err != nil {
		fmt.Printf("Failed to create Merkle tree: %v\n", err)
	} else {
		fmt.Printf("Merkle tree root hash: %x\n", merkleTree.GetRootHash())
	}

	// Start CLI if requested
	enableCLI := true // Could be made a command-line flag
	if enableCLI {
		cli := NewCLI(consensusService, dpki, *nodeName)
		go cli.Run()
	}

	// Wait for context cancellation (SIGINT or SIGTERM)
	<-ctx.Done()
	
	// Clean up
	if consensusService != nil {
		consensusService.Stop()
	}
	
	if fedNode != nil {
		fedNode.Close()
	}
	
	if dpki != nil {
		dpki.Close()
	}
	
	if err := discovery.Stop(); err != nil {
		fmt.Printf("Error stopping discovery service: %v\n", err)
	}
	
	fmt.Println("Bivouac Mesh node shutdown complete")
}