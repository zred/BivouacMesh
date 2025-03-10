package signals

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// SecureChannel represents an encrypted communication channel
type SecureChannel struct {
	localPrivateKey  [32]byte
	localPublicKey   [32]byte
	remotePublicKey  [32]byte
	sharedSecret     [32]byte
	encryptionCipher *chacha20poly1305.AEAD
	decryptionCipher *chacha20poly1305.AEAD
}

// NewSecureChannel creates a new secure channel using X25519 key exchange
func NewSecureChannel() (*SecureChannel, error) {
	var sc SecureChannel

	// Generate local X25519 keypair
	if _, err := io.ReadFull(rand.Reader, sc.localPrivateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Compute public key
	curve25519.ScalarBaseMult(&sc.localPublicKey, &sc.localPrivateKey)

	return &sc, nil
}

// GetPublicKey returns the local public key for key exchange
func (sc *SecureChannel) GetPublicKey() [32]byte {
	return sc.localPublicKey
}

// SetRemotePublicKey sets the remote party's public key and computes the shared secret
func (sc *SecureChannel) SetRemotePublicKey(remotePublicKey [32]byte) error {
	sc.remotePublicKey = remotePublicKey

	// Compute shared secret
	curve25519.ScalarMult(&sc.sharedSecret, &sc.localPrivateKey, &sc.remotePublicKey)

	// Initialize ChaCha20-Poly1305 AEAD for encryption and decryption
	var err error
	sc.encryptionCipher, err = chacha20poly1305.New(sc.sharedSecret[:])
	if err != nil {
		return fmt.Errorf("failed to create encryption cipher: %w", err)
	}

	sc.decryptionCipher, err = chacha20poly1305.New(sc.sharedSecret[:])
	if err != nil {
		return fmt.Errorf("failed to create decryption cipher: %w", err)
	}

	return nil
}

// Encrypt encrypts a message
func (sc *SecureChannel) Encrypt(plaintext []byte) ([]byte, error) {
	if sc.encryptionCipher == nil {
		return nil, errors.New("encryption cipher not initialized, call SetRemotePublicKey first")
	}

	// Generate a random nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the message
	ciphertext := sc.encryptionCipher.Seal(nil, nonce, plaintext, nil)

	// Prepend the nonce to the ciphertext
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a message
func (sc *SecureChannel) Decrypt(ciphertext []byte) ([]byte, error) {
	if sc.decryptionCipher == nil {
		return nil, errors.New("decryption cipher not initialized, call SetRemotePublicKey first")
	}

	// Ensure the ciphertext is long enough
	if len(ciphertext) < chacha20poly1305.NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the nonce and the actual ciphertext
	nonce := ciphertext[:chacha20poly1305.NonceSize]
	actualCiphertext := ciphertext[chacha20poly1305.NonceSize:]

	// Decrypt the message
	plaintext, err := sc.decryptionCipher.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return plaintext, nil
}

// Message represents a secure message in the Bivouac Mesh
type Message struct {
	Sender    []byte // Sender's public key or identity
	Recipient []byte // Recipient's public key or identity (or empty for broadcast)
	Type      uint8  // Message type (e.g., chat, presence, control)
	Payload   []byte // Encrypted payload
	Signature []byte // Signature of the above fields
	Timestamp int64  // Unix timestamp
}

// NewMessage creates a new secure message
func NewMessage(sender, recipient []byte, msgType uint8, payload []byte, signature []byte, timestamp int64) *Message {
	return &Message{
		Sender:    sender,
		Recipient: recipient,
		Type:      msgType,
		Payload:   payload,
		Signature: signature,
		Timestamp: timestamp,
	}
}

// Validate checks if the message structure is valid
func (m *Message) Validate() error {
	if len(m.Sender) == 0 {
		return errors.New("sender is required")
	}
	
	if len(m.Payload) == 0 {
		return errors.New("payload is required")
	}
	
	if len(m.Signature) == 0 {
		return errors.New("signature is required")
	}
	
	if m.Timestamp <= 0 {
		return errors.New("invalid timestamp")
	}
	
	return nil
}