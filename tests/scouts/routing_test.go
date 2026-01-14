package scouts_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/zred/BivouacMesh/pkg/scouts"
)

// Test Bloom filter-based message deduplication
func TestBloomFilterRouting(t *testing.T) {
	// Create a message filter with capacity for 1000 messages and 1% false positive rate
	filter := scouts.NewMessageFilter(1000, 0.01)
	
	// Generate some test message IDs
	messageIDs := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		messageIDs[i] = []byte(fmt.Sprintf("message-%d", i))
	}
	
	// Initially, no messages should be marked as seen
	for i, msgID := range messageIDs {
		if filter.HasSeen(msgID) {
			t.Errorf("Message %d incorrectly marked as seen before insertion", i)
		}
	}
	
	// Mark the first 50 messages as seen
	for i := 0; i < 50; i++ {
		filter.MarkSeen(messageIDs[i])
	}
	
	// Now the first 50 should be seen, the rest should not
	for i, msgID := range messageIDs {
		if i < 50 {
			if !filter.HasSeen(msgID) {
				t.Errorf("Message %d not marked as seen after insertion", i)
			}
		} else {
			if filter.HasSeen(msgID) {
				t.Errorf("Message %d incorrectly marked as seen without insertion", i)
			}
		}
	}
	
	// Test with duplicate message IDs
	duplicateID := []byte("duplicate-message")
	
	if filter.HasSeen(duplicateID) {
		t.Error("Duplicate message incorrectly marked as seen before insertion")
	}
	
	filter.MarkSeen(duplicateID)
	
	if !filter.HasSeen(duplicateID) {
		t.Error("Duplicate message not marked as seen after insertion")
	}
	
	// Mark the same message again
	filter.MarkSeen(duplicateID)
	
	// Should still be marked as seen
	if !filter.HasSeen(duplicateID) {
		t.Error("Duplicate message not marked as seen after second insertion")
	}
}

// Test Merkle tree-based data integrity verification
func TestMerkleTreeVerification(t *testing.T) {
	// Create test data blocks
	dataBlocks := [][]byte{
		[]byte("Block 1 data"),
		[]byte("Block 2 data"),
		[]byte("Block 3 data"),
		[]byte("Block 4 data"),
	}
	
	// Create a Merkle tree from the data blocks
	merkleTree, err := scouts.NewMerkleTree(dataBlocks)
	if err != nil {
		t.Fatalf("Failed to create Merkle tree: %v", err)
	}
	
	// Get the root hash
	rootHash := merkleTree.GetRootHash()
	if rootHash == nil || len(rootHash) == 0 {
		t.Fatal("Root hash is nil or empty")
	}
	
	// Generate proof for the first data block
	proof, err := merkleTree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}
	
	// Verify the proof
	if !merkleTree.VerifyData(dataBlocks[0], proof, 0) {
		t.Error("Proof verification failed for valid data")
	}
	
	// Verify with modified data
	modifiedData := []byte("Modified data")
	if merkleTree.VerifyData(modifiedData, proof, 0) {
		t.Error("Proof verification succeeded with modified data, should have failed")
	}
	
	// Generate proofs for other blocks
	for i := 1; i < len(dataBlocks); i++ {
		proof, err := merkleTree.GenerateProof(i)
		if err != nil {
			t.Fatalf("Failed to generate proof for block %d: %v", i, err)
		}
		
		// Verify the proof
		if !merkleTree.VerifyData(dataBlocks[i], proof, i) {
			t.Errorf("Proof verification failed for valid data at index %d", i)
		}
	}
	
	// Test with empty data
	_, err = scouts.NewMerkleTree([][]byte{})
	if err == nil {
		t.Error("Creating Merkle tree with empty data should have failed")
	}
	
	// Test with a single data block
	singleBlock := [][]byte{[]byte("Single block")}
	singleTree, err := scouts.NewMerkleTree(singleBlock)
	if err != nil {
		t.Fatalf("Failed to create Merkle tree with single block: %v", err)
	}
	
	// The root hash should match the hash of the single block
	expectedHash := sha256.Sum256(singleBlock[0])
	if !bytes.Equal(singleTree.GetRootHash(), expectedHash[:]) {
		t.Error("Root hash of single-block tree should match the hash of the block")
	}
	
	// Test proof for single block
	singleProof, err := singleTree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof for single block: %v", err)
	}
	
	// Verify the proof
	if !singleTree.VerifyData(singleBlock[0], singleProof, 0) {
		t.Error("Proof verification failed for single block")
	}
}