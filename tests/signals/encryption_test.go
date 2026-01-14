package signals_test

import (
	"bytes"
	"testing"

	"github.com/zred/BivouacMesh/pkg/signals"
)

// TestSecureChannelCreation tests creating a secure channel
func TestSecureChannelCreation(t *testing.T) {
	// Create a new secure channel
	channel, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create secure channel: %v", err)
	}

	// Verify the public key is generated
	publicKey := channel.GetPublicKey()
	allZeros := true
	for _, b := range publicKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Public key is all zeros (not generated)")
	}
}

// TestKeyExchange tests X25519 key exchange between two channels
func TestKeyExchange(t *testing.T) {
	// Create two secure channels (Alice and Bob)
	alice, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Alice's channel: %v", err)
	}

	bob, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Bob's channel: %v", err)
	}

	// Exchange public keys
	alicePublicKey := alice.GetPublicKey()
	bobPublicKey := bob.GetPublicKey()

	// Set remote public keys
	err = alice.SetRemotePublicKey(bobPublicKey)
	if err != nil {
		t.Fatalf("Alice failed to set Bob's public key: %v", err)
	}

	err = bob.SetRemotePublicKey(alicePublicKey)
	if err != nil {
		t.Fatalf("Bob failed to set Alice's public key: %v", err)
	}
}

// TestEncryptionDecryption tests end-to-end encryption and decryption
func TestEncryptionDecryption(t *testing.T) {
	// Create two secure channels (Alice and Bob)
	alice, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Alice's channel: %v", err)
	}

	bob, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Bob's channel: %v", err)
	}

	// Exchange public keys
	alicePublicKey := alice.GetPublicKey()
	bobPublicKey := bob.GetPublicKey()

	err = alice.SetRemotePublicKey(bobPublicKey)
	if err != nil {
		t.Fatalf("Alice failed to set Bob's public key: %v", err)
	}

	err = bob.SetRemotePublicKey(alicePublicKey)
	if err != nil {
		t.Fatalf("Bob failed to set Alice's public key: %v", err)
	}

	// Test message
	plaintext := []byte("Hello, secure world!")

	// Alice encrypts a message
	ciphertext, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Alice failed to encrypt message: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext is the same as plaintext (encryption may have failed)")
	}

	// Verify ciphertext is longer (includes nonce)
	if len(ciphertext) <= len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext (includes nonce and authentication tag)")
	}

	// Bob decrypts the message
	decrypted, err := bob.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Bob failed to decrypt message: %v", err)
	}

	// Verify decrypted message matches original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted message doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestEncryptionWithoutKeyExchange tests that encryption fails without key exchange
func TestEncryptionWithoutKeyExchange(t *testing.T) {
	// Create a secure channel without setting remote public key
	channel, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create secure channel: %v", err)
	}

	// Try to encrypt without key exchange
	plaintext := []byte("This should fail")
	_, err = channel.Encrypt(plaintext)
	if err == nil {
		t.Error("Encryption should fail without key exchange, but it succeeded")
	}
}

// TestDecryptionWithoutKeyExchange tests that decryption fails without key exchange
func TestDecryptionWithoutKeyExchange(t *testing.T) {
	// Create a secure channel without setting remote public key
	channel, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create secure channel: %v", err)
	}

	// Try to decrypt without key exchange
	fakeCiphertext := []byte("fake ciphertext data here")
	_, err = channel.Decrypt(fakeCiphertext)
	if err == nil {
		t.Error("Decryption should fail without key exchange, but it succeeded")
	}
}

// TestTamperedCiphertext tests that tampering with ciphertext is detected
func TestTamperedCiphertext(t *testing.T) {
	// Create two secure channels
	alice, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Alice's channel: %v", err)
	}

	bob, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Bob's channel: %v", err)
	}

	// Exchange keys
	alice.SetRemotePublicKey(bob.GetPublicKey())
	bob.SetRemotePublicKey(alice.GetPublicKey())

	// Encrypt a message
	plaintext := []byte("Important message")
	ciphertext, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Tamper with the ciphertext
	if len(ciphertext) > 20 {
		ciphertext[20] ^= 0xFF // Flip some bits
	}

	// Try to decrypt tampered ciphertext
	_, err = bob.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decryption should fail with tampered ciphertext, but it succeeded")
	}
}

// TestShortCiphertext tests that short ciphertexts are rejected
func TestShortCiphertext(t *testing.T) {
	// Create two secure channels
	alice, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Alice's channel: %v", err)
	}

	bob, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Bob's channel: %v", err)
	}

	// Exchange keys
	alice.SetRemotePublicKey(bob.GetPublicKey())
	bob.SetRemotePublicKey(alice.GetPublicKey())

	// Try to decrypt a ciphertext that's too short
	shortCiphertext := []byte("short")
	_, err = bob.Decrypt(shortCiphertext)
	if err == nil {
		t.Error("Decryption should fail with short ciphertext, but it succeeded")
	}
}

// TestMultipleMessages tests encrypting and decrypting multiple messages
func TestMultipleMessages(t *testing.T) {
	// Create two secure channels
	alice, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Alice's channel: %v", err)
	}

	bob, err := signals.NewSecureChannel()
	if err != nil {
		t.Fatalf("Failed to create Bob's channel: %v", err)
	}

	// Exchange keys
	alice.SetRemotePublicKey(bob.GetPublicKey())
	bob.SetRemotePublicKey(alice.GetPublicKey())

	// Test multiple messages
	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2 is longer"),
		[]byte("Message 3 has special chars: !@#$%^&*()"),
		[]byte(""),
	}

	for i, plaintext := range messages {
		// Encrypt
		ciphertext, err := alice.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt message %d: %v", i, err)
		}

		// Decrypt
		decrypted, err := bob.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message %d: %v", i, err)
		}

		// Verify
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Message %d doesn't match after decryption", i)
		}
	}
}

// TestMessageStructure tests the Message structure
func TestMessageStructure(t *testing.T) {
	sender := []byte("alice-public-key")
	recipient := []byte("bob-public-key")
	payload := []byte("encrypted payload data")
	signature := []byte("signature data")
	timestamp := int64(1234567890)

	msg := signals.NewMessage(sender, recipient, 1, payload, signature, timestamp)

	// Verify all fields are set correctly
	if !bytes.Equal(msg.Sender, sender) {
		t.Error("Sender field not set correctly")
	}
	if !bytes.Equal(msg.Recipient, recipient) {
		t.Error("Recipient field not set correctly")
	}
	if msg.Type != 1 {
		t.Error("Type field not set correctly")
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Error("Payload field not set correctly")
	}
	if !bytes.Equal(msg.Signature, signature) {
		t.Error("Signature field not set correctly")
	}
	if msg.Timestamp != timestamp {
		t.Error("Timestamp field not set correctly")
	}
}

// TestMessageValidation tests message validation
func TestMessageValidation(t *testing.T) {
	// Valid message
	validMsg := signals.NewMessage(
		[]byte("sender"),
		[]byte("recipient"),
		1,
		[]byte("payload"),
		[]byte("signature"),
		1234567890,
	)

	if err := validMsg.Validate(); err != nil {
		t.Errorf("Valid message failed validation: %v", err)
	}

	// Test missing sender
	invalidMsg := signals.NewMessage(
		[]byte{}, // empty sender
		[]byte("recipient"),
		1,
		[]byte("payload"),
		[]byte("signature"),
		1234567890,
	)
	if err := invalidMsg.Validate(); err == nil {
		t.Error("Message with empty sender should fail validation")
	}

	// Test missing payload
	invalidMsg = signals.NewMessage(
		[]byte("sender"),
		[]byte("recipient"),
		1,
		[]byte{}, // empty payload
		[]byte("signature"),
		1234567890,
	)
	if err := invalidMsg.Validate(); err == nil {
		t.Error("Message with empty payload should fail validation")
	}

	// Test missing signature
	invalidMsg = signals.NewMessage(
		[]byte("sender"),
		[]byte("recipient"),
		1,
		[]byte("payload"),
		[]byte{}, // empty signature
		1234567890,
	)
	if err := invalidMsg.Validate(); err == nil {
		t.Error("Message with empty signature should fail validation")
	}

	// Test invalid timestamp
	invalidMsg = signals.NewMessage(
		[]byte("sender"),
		[]byte("recipient"),
		1,
		[]byte("payload"),
		[]byte("signature"),
		0, // invalid timestamp
	)
	if err := invalidMsg.Validate(); err == nil {
		t.Error("Message with zero timestamp should fail validation")
	}
}
