package scouts

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
)

// MessageFilter uses Bloom filters for efficient message deduplication
type MessageFilter struct {
	filter    *bloom.BloomFilter
	capacity  uint
	mutex     sync.RWMutex
	seenCount uint
}

// NewMessageFilter creates a new message filter with the given capacity and false positive rate
func NewMessageFilter(capacity uint, falsePositiveRate float64) *MessageFilter {
	// Calculate optimal filter parameters
	m, k := bloom.EstimateParameters(capacity, falsePositiveRate)

	return &MessageFilter{
		filter:    bloom.New(m, k),
		capacity:  capacity,
		seenCount: 0,
	}
}

// HasSeen checks if a message has been seen before
func (mf *MessageFilter) HasSeen(msgID []byte) bool {
	mf.mutex.RLock()
	defer mf.mutex.RUnlock()
	
	// Use SHA-256 to get a consistent hash of the message ID
	hash := sha256.Sum256(msgID)
	return mf.filter.Test(hash[:])
}

// MarkSeen marks a message as seen
func (mf *MessageFilter) MarkSeen(msgID []byte) {
	mf.mutex.Lock()
	defer mf.mutex.Unlock()
	
	// Use SHA-256 to get a consistent hash of the message ID
	hash := sha256.Sum256(msgID)
	mf.filter.Add(hash[:])
	mf.seenCount++
	
	// If we've reached capacity, reset the filter
	if mf.seenCount >= mf.capacity {
		mf.filter.ClearAll()
		mf.seenCount = 0
	}
}

// MerkleNode represents a node in a Merkle tree
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  []byte
	Data  []byte // Only leaf nodes have data
}

// MerkleTree is a Merkle tree implementation for data integrity verification
type MerkleTree struct {
	Root *MerkleNode
}

// NewMerkleTree creates a new Merkle tree from the given data blocks
func NewMerkleTree(dataBlocks [][]byte) (*MerkleTree, error) {
	if len(dataBlocks) == 0 {
		return nil, errors.New("cannot create Merkle tree with no data")
	}
	
	// Create leaf nodes
	nodes := make([]*MerkleNode, len(dataBlocks))
	for i, block := range dataBlocks {
		// Hash the data block
		hash := sha256.Sum256(block)
		nodes[i] = &MerkleNode{
			Hash: hash[:],
			Data: block,
		}
	}
	
	// Build the tree bottom-up
	root := buildMerkleTree(nodes)
	
	return &MerkleTree{
		Root: root,
	}, nil
}

// buildMerkleTree builds a Merkle tree from the given nodes
func buildMerkleTree(nodes []*MerkleNode) *MerkleNode {
	if len(nodes) == 1 {
		return nodes[0]
	}
	
	// If odd number of nodes, duplicate the last one
	if len(nodes) % 2 != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}
	
	// Create parent nodes
	parentNodes := make([]*MerkleNode, 0, len(nodes)/2)
	
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]
		
		// Combine and hash the child hashes
		combined := append(left.Hash, right.Hash...)
		hash := sha256.Sum256(combined)
		
		parent := &MerkleNode{
			Left:  left,
			Right: right,
			Hash:  hash[:],
		}
		
		parentNodes = append(parentNodes, parent)
	}
	
	// Recursively build the tree with the parent nodes
	return buildMerkleTree(parentNodes)
}

// GetRootHash returns the root hash of the Merkle tree
func (mt *MerkleTree) GetRootHash() []byte {
	if mt.Root == nil {
		return nil
	}
	return mt.Root.Hash
}

// VerifyData verifies that a data block is part of the Merkle tree
func (mt *MerkleTree) VerifyData(data []byte, proof [][]byte, index int) bool {
	// Hash the data
	hash := sha256.Sum256(data)
	currentHash := hash[:]
	
	// Apply the proof
	for _, sibling := range proof {
		// Determine which side the sibling is on
		if index % 2 == 0 {
			// Current node is left, sibling is right
			combined := append(currentHash, sibling...)
			newHash := sha256.Sum256(combined)
			currentHash = newHash[:]
		} else {
			// Current node is right, sibling is left
			combined := append(sibling, currentHash...)
			newHash := sha256.Sum256(combined)
			currentHash = newHash[:]
		}
		
		// Move up to the parent index
		index = index / 2
	}
	
	// The final hash should match the root hash
	return string(currentHash) == string(mt.GetRootHash())
}

// GenerateProof generates a Merkle proof for the data at the given index
func (mt *MerkleTree) GenerateProof(index int) ([][]byte, error) {
	if mt.Root == nil {
		return nil, errors.New("empty Merkle tree")
	}
	
	// Collect proof as we traverse the tree
	var proof [][]byte
	
	// Start at the root and traverse to the leaf
	current := mt.Root
	depth := 0
	
	// Calculate the number of leaf nodes
	numLeaves := 1
	for current.Left != nil {
		numLeaves *= 2
		current = current.Left
	}
	
	if index < 0 || index >= numLeaves {
		return nil, errors.New("index out of range")
	}
	
	// Reset to root for traversal
	current = mt.Root
	path := index
	
	for current.Left != nil && current.Right != nil {
		depth++
		
		// Determine direction based on the path
		if path%2 == 0 {
			// Go left, add right sibling to proof
			proof = append(proof, current.Right.Hash)
			current = current.Left
		} else {
			// Go right, add left sibling to proof
			proof = append(proof, current.Left.Hash)
			current = current.Right
		}
		
		// Move to next level
		path = path / 2
	}
	
	return proof, nil
}