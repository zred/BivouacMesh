package garrison

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	
	"github.com/yourusername/bivouac-mesh/pkg/perimeter"
)

// ConsensusService manages the capability consensus process
type ConsensusService struct {
	// Identity
	nodeID   string
	identity *perimeter.Identity
	
	// LibP2P components
	host     host.Host
	pubSub   *pubsub.PubSub
	topics   map[string]*pubsub.Topic
	subs     map[string]*pubsub.Subscription
	
	// NATS components
	natsConn  *nats.Conn
	jetStream jetstream.JetStream
	
	// Capability system
	capManager *perimeter.CapabilityManager
	
	// Local state
	knownPeers      map[peer.ID]struct{}
	peerCapabilities map[string]map[perimeter.CapabilityType]int
	pendingVotes     map[string]map[perimeter.CapabilityType][]*perimeter.CapabilityVote
	mu              sync.RWMutex
	
	// Context for operations
	ctx       context.Context
	cancel    context.CancelFunc
}

// ConsensusConfig holds configuration for the consensus service
type ConsensusConfig struct {
	Host      host.Host
	PubSub    *pubsub.PubSub
	Identity  *perimeter.Identity
	NatsConn  *nats.Conn
	JetStream jetstream.JetStream
}

// NewConsensusService creates a new capability consensus service
func NewConsensusService(ctx context.Context, config ConsensusConfig) (*ConsensusService, error) {
	if config.Host == nil {
		return nil, fmt.Errorf("host is required")
	}
	
	if config.Identity == nil {
		return nil, fmt.Errorf("identity is required")
	}
	
	// Create capability manager
	capManager := perimeter.NewCapabilityManager(config.Identity)
	
	// Create service context
	serviceCtx, cancel := context.WithCancel(ctx)
	
	cs := &ConsensusService{
		nodeID:           config.Identity.Cert.Subject.CommonName,
		identity:         config.Identity,
		host:             config.Host,
		pubSub:           config.PubSub,
		natsConn:         config.NatsConn,
		jetStream:        config.JetStream,
		topics:           make(map[string]*pubsub.Topic),
		subs:             make(map[string]*pubsub.Subscription),
		capManager:       capManager,
		knownPeers:       make(map[peer.ID]struct{}),
		peerCapabilities: make(map[string]map[perimeter.CapabilityType]int),
		pendingVotes:     make(map[string]map[perimeter.CapabilityType][]*perimeter.CapabilityVote),
		ctx:              serviceCtx,
		cancel:           cancel,
	}
	
	// Register capability change handler
	capManager.RegisterCapabilityHandler(func(capability *perimeter.Capability) {
		cs.broadcastCapability(capability)
	})
	
	// Register vote handler
	capManager.RegisterVoteHandler(func(vote *perimeter.CapabilityVote) {
		cs.broadcastVote(vote)
	})
	
	return cs, nil
}

// Start initializes and starts the consensus service
func (cs *ConsensusService) Start() error {
	// Connect to core topics
	err := cs.joinTopics()
	if err != nil {
		return fmt.Errorf("failed to join topics: %w", err)
	}
	
	// Set up NATS handlers for federation nodes
	if cs.natsConn != nil && cs.jetStream != nil {
		err := cs.setupNatsHandlers()
		if err != nil {
			return fmt.Errorf("failed to set up NATS handlers: %w", err)
		}
	}
	
	// Start periodic processes
	go cs.periodicCapabilityRefresh()
	go cs.periodicVoteCheck()
	
	return nil
}

// joinTopics subscribes to required pubsub topics
func (cs *ConsensusService) joinTopics() error {
	// Core consensus topics
	topics := []string{
		"bivouac/consensus/capabilities", // For capability announcements
		"bivouac/consensus/votes",        // For votes
		"bivouac/consensus/revocations",  // For capability revocations
	}
	
	for _, topicName := range topics {
		// Join the topic
		topic, err := cs.pubSub.Join(topicName)
		if err != nil {
			return fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}
		
		// Subscribe to the topic
		sub, err := topic.Subscribe()
		if err != nil {
			return fmt.Errorf("failed to subscribe to topic %s: %w", topicName, err)
		}
		
		// Store the topic and subscription
		cs.topics[topicName] = topic
		cs.subs[topicName] = sub
		
		// Start message handler
		go cs.handleMessages(topicName, sub)
	}
	
	return nil
}

// setupNatsHandlers sets up NATS handlers for federation consensus
func (cs *ConsensusService) setupNatsHandlers() error {
	// Create stream for capability consensus
	_, err := cs.jetStream.CreateStream(cs.ctx, jetstream.StreamConfig{
		Name:     "CONSENSUS",
		Subjects: []string{"consensus.>"},
		Storage:  jetstream.MemoryStorage,
	})
	if err != nil {
		return fmt.Errorf("failed to create consensus stream: %w", err)
	}
	
	// Subscribe to capability announcements
	_, err = cs.natsConn.Subscribe("consensus.capability", func(msg *nats.Msg) {
		// Deserialize the capability
		capability, err := perimeter.DeserializeCapability(msg.Data)
		if err != nil {
			// Log error but continue
			fmt.Printf("Error deserializing capability: %v\n", err)
			return
		}
		
		// Process the capability
		err = cs.capManager.AddCapability(capability)
		if err != nil {
			fmt.Printf("Error adding capability: %v\n", err)
			return
		}
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to capability announcements: %w", err)
	}
	
	// Subscribe to votes
	_, err = cs.natsConn.Subscribe("consensus.vote", func(msg *nats.Msg) {
		// Deserialize the vote
		vote, err := perimeter.DeserializeVote(msg.Data)
		if err != nil {
			// Log error but continue
			fmt.Printf("Error deserializing vote: %v\n", err)
			return
		}
		
		// Add the vote to our local store
		cs.mu.Lock()
		defer cs.mu.Unlock()
		
		// Check if we have votes for this node
		nodeVotes, ok := cs.pendingVotes[vote.TargetNode]
		if !ok {
			nodeVotes = make(map[perimeter.CapabilityType][]*perimeter.CapabilityVote)
			cs.pendingVotes[vote.TargetNode] = nodeVotes
		}
		
		// Check if we have votes for this capability
		capVotes, ok := nodeVotes[vote.CapabilityType]
		if !ok {
			capVotes = make([]*perimeter.CapabilityVote, 0)
		}
		
		// Check for existing vote from this voter
		found := false
		for i, existingVote := range capVotes {
			if existingVote.VoterID == vote.VoterID {
				// Replace the existing vote
				capVotes[i] = vote
				found = true
				break
			}
		}
		
		if !found {
			// Add new vote
			capVotes = append(capVotes, vote)
		}
		
		nodeVotes[vote.CapabilityType] = capVotes
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to votes: %w", err)
	}
	
	return nil
}

// handleMessages processes messages from a pubsub topic
func (cs *ConsensusService) handleMessages(topicName string, sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(cs.ctx)
		if err != nil {
			// Context canceled or other error
			return
		}
		
		// Skip messages from ourselves
		if msg.ReceivedFrom == cs.host.ID() {
			continue
		}
		
		// Process based on topic
		switch topicName {
		case "bivouac/consensus/capabilities":
			cs.handleCapabilityMessage(msg)
		case "bivouac/consensus/votes":
			cs.handleVoteMessage(msg)
		case "bivouac/consensus/revocations":
			cs.handleRevocationMessage(msg)
		}
	}
}

// handleCapabilityMessage processes a capability announcement message
func (cs *ConsensusService) handleCapabilityMessage(msg *pubsub.Message) {
	// Deserialize the capability
	capability, err := perimeter.DeserializeCapability(msg.Data)
	if err != nil {
		// Log error but continue
		fmt.Printf("Error deserializing capability: %v\n", err)
		return
	}
	
	// Process the capability
	err = cs.capManager.AddCapability(capability)
	if err != nil {
		fmt.Printf("Error adding capability: %v\n", err)
		return
	}
	
	// Update peer capabilities
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	nodeCaps, ok := cs.peerCapabilities[capability.Subject]
	if !ok {
		nodeCaps = make(map[perimeter.CapabilityType]int)
	}
	
	nodeCaps[capability.Type] = capability.Level
	cs.peerCapabilities[capability.Subject] = nodeCaps
}

// handleVoteMessage processes a vote message
func (cs *ConsensusService) handleVoteMessage(msg *pubsub.Message) {
	// Deserialize the vote
	vote, err := perimeter.DeserializeVote(msg.Data)
	if err != nil {
		// Log error but continue
		fmt.Printf("Error deserializing vote: %v\n", err)
		return
	}
	
	// Add the vote to our local store
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	// Check if we have votes for this node
	nodeVotes, ok := cs.pendingVotes[vote.TargetNode]
	if !ok {
		nodeVotes = make(map[perimeter.CapabilityType][]*perimeter.CapabilityVote)
		cs.pendingVotes[vote.TargetNode] = nodeVotes
	}
	
	// Check if we have votes for this capability
	capVotes, ok := nodeVotes[vote.CapabilityType]
	if !ok {
		capVotes = make([]*perimeter.CapabilityVote, 0)
	}
	
	// Check for existing vote from this voter
	found := false
	for i, existingVote := range capVotes {
		if existingVote.VoterID == vote.VoterID {
			// Replace the existing vote
			capVotes[i] = vote
			found = true
			break
		}
	}
	
	if !found {
		// Add new vote
		capVotes = append(capVotes, vote)
	}
	
	nodeVotes[vote.CapabilityType] = capVotes
}

// handleRevocationMessage processes a capability revocation message
func (cs *ConsensusService) handleRevocationMessage(msg *pubsub.Message) {
	// Parse the revocation
	var revocation struct {
		NodeID     string                `json:"node_id"`
		Capability perimeter.CapabilityType `json:"capability"`
		Reason     string                `json:"reason"`
		Signatures map[string][]byte     `json:"signatures"`
	}
	
	err := json.Unmarshal(msg.Data, &revocation)
	if err != nil {
		fmt.Printf("Error deserializing revocation: %v\n", err)
		return
	}
	
	// TODO: Implement proper revocation by creating a zero-duration capability
	// and validating signatures similar to capability grants
	
	// For now, we just log the revocation
	fmt.Printf("Received revocation for node %s, capability %s: %s\n",
		revocation.NodeID, revocation.Capability, revocation.Reason)
}

// broadcastCapability announces a capability to the network
func (cs *ConsensusService) broadcastCapability(capability *perimeter.Capability) {
	// Serialize the capability
	data, err := perimeter.SerializeCapability(capability)
	if err != nil {
		fmt.Printf("Error serializing capability: %v\n", err)
		return
	}
	
	// Publish to pubsub
	topic, ok := cs.topics["bivouac/consensus/capabilities"]
	if ok {
		err = topic.Publish(cs.ctx, data)
		if err != nil {
			fmt.Printf("Error publishing capability to pubsub: %v\n", err)
		}
	}
	
	// Publish to NATS if available
	if cs.natsConn != nil && cs.jetStream != nil {
		_, err = cs.jetStream.Publish(cs.ctx, "consensus.capability", data)
		if err != nil {
			fmt.Printf("Error publishing capability to NATS: %v\n", err)
		}
	}
}

// broadcastVote announces a vote to the network
func (cs *ConsensusService) broadcastVote(vote *perimeter.CapabilityVote) {
	// Serialize the vote
	data, err := perimeter.SerializeVote(vote)
	if err != nil {
		fmt.Printf("Error serializing vote: %v\n", err)
		return
	}
	
	// Publish to pubsub
	topic, ok := cs.topics["bivouac/consensus/votes"]
	if ok {
		err = topic.Publish(cs.ctx, data)
		if err != nil {
			fmt.Printf("Error publishing vote to pubsub: %v\n", err)
		}
	}
	
	// Publish to NATS if available
	if cs.natsConn != nil && cs.jetStream != nil {
		_, err = cs.jetStream.Publish(cs.ctx, "consensus.vote", data)
		if err != nil {
			fmt.Printf("Error publishing vote to NATS: %v\n", err)
		}
	}
}

// VoteForCapability casts a vote for a capability
func (cs *ConsensusService) VoteForCapability(
	targetNodeID string, 
	targetNodeKey []byte,
	capType perimeter.CapabilityType, 
	level int,
	duration time.Duration) (*perimeter.CapabilityVote, error) {
	
	// Convert the target key to ed25519.PublicKey
	if len(targetNodeKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(targetNodeKey))
	}
	
	var pubKey [32]byte
	copy(pubKey[:], targetNodeKey)
	
	// Calculate expiration
	expiration := time.Now().Add(duration)
	
	// Cast the vote
	vote, err := cs.capManager.VoteForCapability(
		targetNodeID, 
		pubKey[:],
		capType, 
		level,
		expiration)
		
	if err != nil {
		return nil, err
	}
	
	// Broadcast the vote
	cs.broadcastVote(vote)
	
	return vote, nil
}

// periodicCapabilityRefresh periodically checks for capabilities that need renewal
func (cs *ConsensusService) periodicCapabilityRefresh() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-cs.ctx.Done():
			return
		case <-ticker.C:
			// Get our own capabilities
			capabilities := cs.capManager.GetCapabilities(cs.nodeID)
			
			// Check each capability for renewal
			now := time.Now()
			for _, cap := range capabilities {
				timeToExpiration := cap.ExpiresAt.Sub(now)
				
				// Get renewal threshold for this capability type
				req, ok := perimeter.DefaultCapabilityRequirements[cap.Type]
				if !ok {
					continue
				}
				
				// If we're within the renewal window, broadcast a renewal request
				if timeToExpiration <= req.RenewalThreshold {
					// For now, just broadcast the capability to remind others
					cs.broadcastCapability(cap)
					
					// TODO: Implement a specific renewal request mechanism
					fmt.Printf("Capability %s is approaching expiration, requesting renewal\n", cap.Type)
				}
			}
		}
	}
}

// periodicVoteCheck periodically processes pending votes
func (cs *ConsensusService) periodicVoteCheck() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-cs.ctx.Done():
			return
		case <-ticker.C:
			// Process pending votes
			cs.mu.Lock()
			
			// For each node with pending votes
			for nodeID, nodeVotes := range cs.pendingVotes {
				// For each capability type
				for capType, votes := range nodeVotes {
					// Count valid votes
					validVotes := make([]*perimeter.CapabilityVote, 0)
					voterSeen := make(map[string]bool)
					now := time.Now()
					
					for _, vote := range votes {
						// Skip expired votes
						if now.After(vote.Expiration) {
							continue
						}
						
						// Skip duplicate voters
						if _, seen := voterSeen[vote.VoterID]; seen {
							continue
						}
						
						// TODO: Verify the vote signature and capability of the voter
						
						validVotes = append(validVotes, vote)
						voterSeen[vote.VoterID] = true
					}
					
					// Check if we have enough votes
					req, ok := perimeter.DefaultCapabilityRequirements[capType]
					if !ok {
						continue
					}
					
					// Check if this node already has this capability (renewal case)
					hasCapability, _ := cs.capManager.HasCapability(nodeID, capType)
					requiredVotes := req.RequiredVotes
					if hasCapability {
						requiredVotes = req.RenewalRequiredVotes
					}
					
					if len(validVotes) >= requiredVotes {
						// Create a capability from the votes
						if len(validVotes) == 0 {
							continue // Sanity check
						}
						
						// Use the first vote as a template
						firstVote := validVotes[0]
						
						// Find the longest expiration
						expiresAt := firstVote.Expiration
						for _, vote := range validVotes {
							if vote.Expiration.After(expiresAt) {
								expiresAt = vote.Expiration
							}
						}
						
						// Create the capability
						capability := &perimeter.Capability{
							Type:        capType,
							Subject:     nodeID,
							SubjectKey:  firstVote.TargetNodeKey,
							Level:       firstVote.Level,
							GrantedBy:   make([]string, 0),
							Signatures:  make(map[string][]byte),
							IssuedAt:    now,
							ExpiresAt:   expiresAt,
							Constraints: make(map[string]interface{}),
							Metadata:    make(map[string]interface{}),
						}
						
						// Add the grantors and signatures
						for _, vote := range validVotes {
							capability.GrantedBy = append(capability.GrantedBy, vote.VoterID)
							capability.Signatures[vote.VoterID] = vote.Signature
						}
						
						// Add the capability to the manager
						err := cs.capManager.AddCapability(capability)
						if err != nil {
							fmt.Printf("Error adding capability from votes: %v\n", err)
							continue
						}
						
						// Capability added successfully, clear the votes
						delete(nodeVotes, capType)
					}
				}
				
				// If no capabilities left, clean up
				if len(nodeVotes) == 0 {
					delete(cs.pendingVotes, nodeID)
				}
			}
			
			cs.mu.Unlock()
		}
	}
}

// GetNodeCapabilities returns the capabilities for a node
func (cs *ConsensusService) GetNodeCapabilities(nodeID string) []*perimeter.Capability {
	return cs.capManager.GetCapabilities(nodeID)
}

// HasCapability checks if a node has a specific capability
func (cs *ConsensusService) HasCapability(nodeID string, capType perimeter.CapabilityType) (bool, int) {
	return cs.capManager.HasCapability(nodeID, capType)
}

// Stop shuts down the consensus service
func (cs *ConsensusService) Stop() error {
	cs.cancel()
	
	// Close subscriptions
	for _, sub := range cs.subs {
		sub.Cancel()
	}
	
	return nil
}