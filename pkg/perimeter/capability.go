package perimeter

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CapabilityType represents different types of capabilities a node can have
type CapabilityType string

const (
	// Core capability types
	CapabilityRootAnchor     CapabilityType = "root-anchor"     // Can grant any capability
	CapabilityCA             CapabilityType = "ca"              // Can issue certificates
	CapabilityFederation     CapabilityType = "federation"      // Can operate federation services
	CapabilityGateway        CapabilityType = "gateway"         // Can serve as network gateway
	CapabilityStorage        CapabilityType = "storage"         // Can provide persistent storage
	CapabilityRelay          CapabilityType = "relay"           // Can relay messages
	CapabilityValidator      CapabilityType = "validator"       // Can validate messages or transactions
	CapabilityConsensusVoter CapabilityType = "consensus-voter" // Can participate in consensus
)

// CapabilityRequirement defines the voting requirements to grant a capability
type CapabilityRequirement struct {
	CapabilityType      CapabilityType // What capability this requirement is for
	RequiredVotes       int            // Number of votes required to grant
	RequiredCapability  CapabilityType // What capability voters must have
	MinVoterCapability  int            // Minimum level of voter capability 
	ExpirationDuration  time.Duration  // How long the capability lasts
	RenewalThreshold    time.Duration  // When renewal should begin before expiration
	RenewalRequiredVotes int           // Votes required for renewal (typically less than initial grant)
}

// DefaultCapabilityRequirements provides the network defaults for capability promotion
var DefaultCapabilityRequirements = map[CapabilityType]CapabilityRequirement{
	CapabilityRootAnchor: {
		CapabilityType:      CapabilityRootAnchor,
		RequiredVotes:       5,                        // Bootstrap requires more votes
		RequiredCapability:  CapabilityConsensusVoter, // Bootstrap from consensus voters
		MinVoterCapability:  1,                        // Any voter level is fine for bootstrap
		ExpirationDuration:  8760 * time.Hour,         // 1 year
		RenewalThreshold:    720 * time.Hour,          // 30 days before expiration
		RenewalRequiredVotes: 3,                       // Renewal needs fewer votes
	},
	CapabilityCA: {
		CapabilityType:      CapabilityCA,
		RequiredVotes:       3,
		RequiredCapability:  CapabilityRootAnchor,
		MinVoterCapability:  1,
		ExpirationDuration:  8760 * time.Hour, // 1 year
		RenewalThreshold:    720 * time.Hour,  // 30 days before expiration
		RenewalRequiredVotes: 2,
	},
	CapabilityFederation: {
		CapabilityType:      CapabilityFederation,
		RequiredVotes:       3,
		RequiredCapability:  CapabilityRootAnchor,
		MinVoterCapability:  1,
		ExpirationDuration:  8760 * time.Hour, // 1 year
		RenewalThreshold:    720 * time.Hour,  // 30 days before expiration
		RenewalRequiredVotes: 2,
	},
	CapabilityGateway: {
		CapabilityType:      CapabilityGateway,
		RequiredVotes:       2,
		RequiredCapability:  CapabilityCA,
		MinVoterCapability:  1,
		ExpirationDuration:  2160 * time.Hour, // 90 days
		RenewalThreshold:    168 * time.Hour,  // 7 days before expiration
		RenewalRequiredVotes: 1,
	},
	CapabilityStorage: {
		CapabilityType:      CapabilityStorage,
		RequiredVotes:       2,
		RequiredCapability:  CapabilityCA,
		MinVoterCapability:  1,
		ExpirationDuration:  2160 * time.Hour, // 90 days
		RenewalThreshold:    168 * time.Hour,  // 7 days before expiration
		RenewalRequiredVotes: 1,
	},
	CapabilityRelay: {
		CapabilityType:      CapabilityRelay,
		RequiredVotes:       2,
		RequiredCapability:  CapabilityFederation,
		MinVoterCapability:  1,
		ExpirationDuration:  720 * time.Hour, // 30 days
		RenewalThreshold:    72 * time.Hour,  // 3 days before expiration
		RenewalRequiredVotes: 1,
	},
	CapabilityValidator: {
		CapabilityType:      CapabilityValidator,
		RequiredVotes:       2,
		RequiredCapability:  CapabilityFederation,
		MinVoterCapability:  1,
		ExpirationDuration:  720 * time.Hour, // 30 days
		RenewalThreshold:    72 * time.Hour,  // 3 days before expiration
		RenewalRequiredVotes: 1,
	},
	CapabilityConsensusVoter: {
		CapabilityType:      CapabilityConsensusVoter,
		RequiredVotes:       2,
		RequiredCapability:  CapabilityRootAnchor,
		MinVoterCapability:  1,
		ExpirationDuration:  4320 * time.Hour, // 180 days
		RenewalThreshold:    168 * time.Hour,  // 7 days before expiration
		RenewalRequiredVotes: 1,
	},
}

// Capability represents a capability granted to a node
type Capability struct {
	Type        CapabilityType        // Type of capability
	Subject     string                // Node identifier this capability is for
	SubjectKey  ed25519.PublicKey     // Node's public key
	Level       int                   // Capability level (some capabilities have tiers)
	GrantedBy   []string              // Who granted this capability
	Signatures  map[string][]byte     // Signatures from the grantors
	IssuedAt    time.Time             // When this capability was issued
	ExpiresAt   time.Time             // When this capability expires
	Constraints map[string]interface{} // Optional constraints on the capability
	Metadata    map[string]interface{} // Optional metadata
}

// CapabilityVote represents a vote to grant a capability
type CapabilityVote struct {
	VoterID        string            // ID of the voter
	VoterKey       ed25519.PublicKey // Public key of the voter
	VoterCapability CapabilityType   // Capability type of the voter
	TargetNode     string            // Node receiving the capability
	TargetNodeKey  ed25519.PublicKey // Public key of target node
	CapabilityType CapabilityType    // Capability being voted on
	Level          int               // Level of capability
	Timestamp      time.Time         // When the vote was cast
	Expiration     time.Time         // When the capability would expire if granted
	Signature      []byte            // Signature of the voter
	Metadata       map[string]string // Optional metadata
}

// CapabilityManager handles capability consensus and grants
type CapabilityManager struct {
	identity           *Identity
	capabilities       map[string][]*Capability       // Node ID -> capabilities
	votes              map[string][]*CapabilityVote   // Target Node ID -> votes
	capabilityRequirements map[CapabilityType]CapabilityRequirement
	mu                 sync.RWMutex
	capabilityHandlers []func(*Capability)            // Handlers for capability changes
	voteHandlers       []func(*CapabilityVote)        // Handlers for votes
}

// NewCapabilityManager creates a new capability manager
func NewCapabilityManager(identity *Identity) *CapabilityManager {
	return &CapabilityManager{
		identity:           identity,
		capabilities:       make(map[string][]*Capability),
		votes:              make(map[string][]*CapabilityVote),
		capabilityRequirements: DefaultCapabilityRequirements,
		capabilityHandlers: make([]func(*Capability), 0),
		voteHandlers:       make([]func(*CapabilityVote), 0),
	}
}

// HasCapability checks if a node has a specific capability
func (cm *CapabilityManager) HasCapability(nodeID string, capType CapabilityType) (bool, int) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	nodeCaps, ok := cm.capabilities[nodeID]
	if !ok {
		return false, 0
	}
	
	now := time.Now()
	
	for _, cap := range nodeCaps {
		if cap.Type == capType && now.Before(cap.ExpiresAt) {
			return true, cap.Level
		}
	}
	
	return false, 0
}

// AddCapability adds a capability for a node
func (cm *CapabilityManager) AddCapability(capability *Capability) error {
	if capability == nil {
		return errors.New("capability cannot be nil")
	}
	
	// Verify that the capability has sufficient signatures
	req, ok := cm.capabilityRequirements[capability.Type]
	if !ok {
		return fmt.Errorf("unknown capability type: %s", capability.Type)
	}
	
	if len(capability.Signatures) < req.RequiredVotes {
		return fmt.Errorf("insufficient signatures: got %d, need %d", 
			len(capability.Signatures), req.RequiredVotes)
	}
	
	// Verify all signatures
	// In a real implementation, this would verify that each signer has
	// the required capability to grant this capability
	for grantor, _ := range capability.Signatures {
		// Verify the signature
		// This would involve fetching the grantor's public key and verifying
		// the signature against the capability data
		
		// Also verify that the grantor has the required capability to grant
		hasReq, level := cm.HasCapability(grantor, req.RequiredCapability)
		if !hasReq || level < req.MinVoterCapability {
			return fmt.Errorf("grantor %s does not have required capability", grantor)
		}
	}
	
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Add or update the capability
	caps, ok := cm.capabilities[capability.Subject]
	if !ok {
		caps = make([]*Capability, 0)
	}
	
	// Check if this capability already exists and update it
	for i, cap := range caps {
		if cap.Type == capability.Type {
			// Update existing capability
			caps[i] = capability
			cm.capabilities[capability.Subject] = caps
			
			// Notify handlers
			for _, handler := range cm.capabilityHandlers {
				go handler(capability)
			}
			
			return nil
		}
	}
	
	// Add new capability
	caps = append(caps, capability)
	cm.capabilities[capability.Subject] = caps
	
	// Notify handlers
	for _, handler := range cm.capabilityHandlers {
		go handler(capability)
	}
	
	return nil
}

// VoteForCapability casts a vote to grant a capability
func (cm *CapabilityManager) VoteForCapability(
	targetNodeID string, 
	targetNodeKey ed25519.PublicKey,
	capType CapabilityType, 
	level int,
	expiration time.Time) (*CapabilityVote, error) {
	
	// Check if this node can vote for this capability
	req, ok := cm.capabilityRequirements[capType]
	if !ok {
		return nil, fmt.Errorf("unknown capability type: %s", capType)
	}
	
	// Check if this node has the required capability to vote
	nodeID := cm.identity.Cert.Subject.CommonName
	hasReq, nodeLevel := cm.HasCapability(nodeID, req.RequiredCapability)
	if !hasReq {
		return nil, fmt.Errorf("this node does not have the %s capability required to vote", 
			req.RequiredCapability)
	}
	
	if nodeLevel < req.MinVoterCapability {
		return nil, fmt.Errorf("this node's capability level (%d) is below the required level (%d)",
			nodeLevel, req.MinVoterCapability)
	}
	
	// Create the vote
	vote := &CapabilityVote{
		VoterID:        nodeID,
		VoterKey:       cm.identity.PublicKey,
		VoterCapability: req.RequiredCapability,
		TargetNode:     targetNodeID,
		TargetNodeKey:  targetNodeKey,
		CapabilityType: capType,
		Level:          level,
		Timestamp:      time.Now(),
		Expiration:     expiration,
		Metadata:       make(map[string]string),
	}
	
	// Sign the vote
	voteData, err := json.Marshal(map[string]interface{}{
		"voter":         vote.VoterID,
		"target":        vote.TargetNode,
		"capability":    vote.CapabilityType,
		"level":         vote.Level,
		"timestamp":     vote.Timestamp.Unix(),
		"expiration":    vote.Expiration.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vote data: %w", err)
	}
	
	vote.Signature, err = cm.identity.Sign(voteData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vote: %w", err)
	}
	
	// Add the vote to our local store
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	votes, ok := cm.votes[targetNodeID]
	if !ok {
		votes = make([]*CapabilityVote, 0)
	}
	
	// Check for duplicate votes
	for i, v := range votes {
		if v.VoterID == vote.VoterID && v.CapabilityType == vote.CapabilityType {
			// Replace the existing vote
			votes[i] = vote
			cm.votes[targetNodeID] = votes
			
			// Notify handlers
			for _, handler := range cm.voteHandlers {
				go handler(vote)
			}
			
			// Check if we have enough votes to grant the capability
			cm.checkVotesForCapability(targetNodeID, capType)
			
			return vote, nil
		}
	}
	
	// Add new vote
	votes = append(votes, vote)
	cm.votes[targetNodeID] = votes
	
	// Notify handlers
	for _, handler := range cm.voteHandlers {
		go handler(vote)
	}
	
	// Check if we have enough votes to grant the capability
	cm.checkVotesForCapability(targetNodeID, capType)
	
	return vote, nil
}

// checkVotesForCapability checks if a node has received enough votes to be granted a capability
func (cm *CapabilityManager) checkVotesForCapability(nodeID string, capType CapabilityType) {
	votes, ok := cm.votes[nodeID]
	if !ok {
		return
	}
	
	req, ok := cm.capabilityRequirements[capType]
	if !ok {
		return
	}
	
	// Count valid votes for this capability
	validVotes := make([]*CapabilityVote, 0)
	voterMap := make(map[string]bool)
	now := time.Now()
	
	for _, vote := range votes {
		// Only count votes for this capability type
		if vote.CapabilityType != capType {
			continue
		}
		
		// Check if the vote is expired
		if now.After(vote.Expiration) {
			continue
		}
		
		// Check for duplicate voters (only count the latest vote from each voter)
		if _, exists := voterMap[vote.VoterID]; exists {
			continue
		}
		
		// Verify the voter has the required capability
		hasReq, level := cm.HasCapability(vote.VoterID, req.RequiredCapability)
		if !hasReq || level < req.MinVoterCapability {
			continue
		}
		
		// This vote is valid
		validVotes = append(validVotes, vote)
		voterMap[vote.VoterID] = true
	}
	
	// Check if we have enough votes
	isRenewal := false
	
	// See if this is a renewal
	hasCapability, _ := cm.HasCapability(nodeID, capType)
	if hasCapability {
		isRenewal = true
	}
	
	requiredVotes := req.RequiredVotes
	if isRenewal {
		requiredVotes = req.RenewalRequiredVotes
	}
	
	if len(validVotes) >= requiredVotes {
		// We have enough votes to grant the capability!
		// Get the target node details
		if len(validVotes) == 0 {
			return // Sanity check
		}
		
		targetNodeID := validVotes[0].TargetNode
		targetNodeKey := validVotes[0].TargetNodeKey
		expiresAt := validVotes[0].Expiration // Use the first vote's expiration
		
		// Find the longest expiration
		for _, vote := range validVotes {
			if vote.Expiration.After(expiresAt) {
				expiresAt = vote.Expiration
			}
		}
		
		// Create the capability
		capability := &Capability{
			Type:        capType,
			Subject:     targetNodeID,
			SubjectKey:  targetNodeKey,
			Level:       validVotes[0].Level, // Use the level from the first vote
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
		
		// Add the capability
		caps, ok := cm.capabilities[targetNodeID]
		if !ok {
			caps = make([]*Capability, 0)
		}
		
		// Update or add the capability
		found := false
		for i, cap := range caps {
			if cap.Type == capType {
				// Update existing capability
				caps[i] = capability
				found = true
				break
			}
		}
		
		if !found {
			// Add new capability
			caps = append(caps, capability)
		}
		
		cm.capabilities[targetNodeID] = caps
		
		// Notify handlers
		for _, handler := range cm.capabilityHandlers {
			go handler(capability)
		}
	}
}

// GetCapabilities returns all capabilities for a node
func (cm *CapabilityManager) GetCapabilities(nodeID string) []*Capability {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	caps, ok := cm.capabilities[nodeID]
	if !ok {
		return []*Capability{}
	}
	
	// Filter out expired capabilities
	now := time.Now()
	validCaps := make([]*Capability, 0)
	
	for _, cap := range caps {
		if now.Before(cap.ExpiresAt) {
			validCaps = append(validCaps, cap)
		}
	}
	
	return validCaps
}

// GetVotes returns all votes for a node
func (cm *CapabilityManager) GetVotes(nodeID string) []*CapabilityVote {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	votes, ok := cm.votes[nodeID]
	if !ok {
		return []*CapabilityVote{}
	}
	
	return votes
}

// SerializeCapability converts a capability to JSON
func SerializeCapability(capability *Capability) ([]byte, error) {
	return json.Marshal(capability)
}

// DeserializeCapability parses a capability from JSON
func DeserializeCapability(data []byte) (*Capability, error) {
	var cap Capability
	err := json.Unmarshal(data, &cap)
	if err != nil {
		return nil, err
	}
	return &cap, nil
}

// SerializeVote converts a vote to JSON
func SerializeVote(vote *CapabilityVote) ([]byte, error) {
	return json.Marshal(vote)
}

// DeserializeVote parses a vote from JSON
func DeserializeVote(data []byte) (*CapabilityVote, error) {
	var vote CapabilityVote
	err := json.Unmarshal(data, &vote)
	if err != nil {
		return nil, err
	}
	return &vote, nil
}

// RegisterCapabilityHandler registers a handler for capability changes
func (cm *CapabilityManager) RegisterCapabilityHandler(handler func(*Capability)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.capabilityHandlers = append(cm.capabilityHandlers, handler)
}

// RegisterVoteHandler registers a handler for votes
func (cm *CapabilityManager) RegisterVoteHandler(handler func(*CapabilityVote)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.voteHandlers = append(cm.voteHandlers, handler)
}