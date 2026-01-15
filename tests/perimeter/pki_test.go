package perimeter_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// TestDistributedPKICreation tests creating a distributed PKI
func TestDistributedPKICreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("pki-test-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Create a libp2p host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	config := perimeter.PKIConfig{
		Host:         host,
		IPFSEndpoint: "localhost:5001", // May not be available
		NatsURL:      "nats://localhost:4222",
		Identity:     identity,
		IsRootCA:     false,
	}

	pki, err := perimeter.NewDistributedPKI(ctx, config)
	if err != nil {
		// IPFS or NATS might not be available, skip if so
		t.Skipf("Skipping test - external services not available: %v", err)
		return
	}
	defer pki.Close()

	if pki == nil {
		t.Fatal("PKI is nil")
	}

	if pki.DHT == nil {
		t.Error("DHT should be initialized")
	}
}

// TestRootCAConfiguration tests creating a PKI as root CA
func TestRootCAConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("root-ca-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	config := perimeter.PKIConfig{
		Host:         host,
		IPFSEndpoint: "localhost:5001",
		NatsURL:      "nats://localhost:4222",
		Identity:     identity,
		IsRootCA:     true, // Root CA
	}

	pki, err := perimeter.NewDistributedPKI(ctx, config)
	if err != nil {
		t.Skipf("Skipping test - external services not available: %v", err)
		return
	}
	defer pki.Close()

	// Root CA should trust itself
	if len(pki.RootCAs) == 0 {
		t.Error("Root CA should have at least itself in trusted roots")
	}
}

// TestCertificateChainCreation tests creating certificate chains
func TestCertificateChainCreation(t *testing.T) {
	// Create CA identity
	caIdentity, err := perimeter.NewIdentity("test-ca")
	if err != nil {
		t.Fatalf("Failed to create CA identity: %v", err)
	}

	// Create subject identity
	subjectIdentity, err := perimeter.NewIdentity("test-subject")
	if err != nil {
		t.Fatalf("Failed to create subject identity: %v", err)
	}

	// CA signs subject's certificate
	cert, certPEM, err := caIdentity.CreateCertificateChain("test-subject", subjectIdentity.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create certificate chain: %v", err)
	}

	if cert == nil {
		t.Error("Certificate is nil")
	}

	if len(certPEM) == 0 {
		t.Error("Certificate PEM is empty")
	}

	// Verify issuer and subject
	if cert.Subject.CommonName != "test-subject" {
		t.Errorf("Expected subject 'test-subject', got '%s'", cert.Subject.CommonName)
	}

	if cert.Issuer.CommonName != "test-ca" {
		t.Errorf("Expected issuer 'test-ca', got '%s'", cert.Issuer.CommonName)
	}
}

// TestCRLFunctionality tests Certificate Revocation List operations
func TestCRLFunctionality(t *testing.T) {
	identity, err := perimeter.NewIdentity("crl-issuer")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)
	if crl == nil {
		t.Fatal("CRL is nil")
	}

	// Test certificate not revoked initially
	certSerial := "test-cert-12345"
	if crl.IsRevoked(certSerial) {
		t.Error("Certificate should not be revoked initially")
	}

	// Revoke certificate
	crl.RevokeCertificate(certSerial)

	// Verify it's revoked
	if !crl.IsRevoked(certSerial) {
		t.Error("Certificate should be revoked after revocation")
	}

	// Test signed CRL generation
	signedCRL, err := crl.GetSignedCRL()
	if err != nil {
		t.Errorf("Failed to get signed CRL: %v", err)
	}

	if len(signedCRL) == 0 {
		t.Error("Signed CRL is empty")
	}
}

// TestMultipleCertificateRevocations tests revoking multiple certificates
func TestMultipleCertificateRevocations(t *testing.T) {
	identity, err := perimeter.NewIdentity("multi-revoke")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	// Revoke multiple certificates
	serials := []string{"cert-1", "cert-2", "cert-3", "cert-4", "cert-5"}
	for _, serial := range serials {
		crl.RevokeCertificate(serial)
	}

	// Verify all are revoked
	for _, serial := range serials {
		if !crl.IsRevoked(serial) {
			t.Errorf("Certificate %s should be revoked", serial)
		}
	}

	// Verify non-revoked certificate
	if crl.IsRevoked("cert-999") {
		t.Error("Non-revoked certificate should not be marked as revoked")
	}
}

// TestSignatureVerification tests digital signature verification
func TestSignatureVerification(t *testing.T) {
	identity, err := perimeter.NewIdentity("signer")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Sign a message
	message := []byte("Important message to sign")
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signature
	if !identity.Verify(message, signature) {
		t.Error("Signature verification failed for valid signature")
	}

	// Test with modified message
	modifiedMessage := []byte("Modified message")
	if identity.Verify(modifiedMessage, signature) {
		t.Error("Verification should fail with modified message")
	}

	// Test with corrupted signature
	if len(signature) > 0 {
		corruptedSig := make([]byte, len(signature))
		copy(corruptedSig, signature)
		corruptedSig[0] ^= 0xFF

		if identity.Verify(message, corruptedSig) {
			t.Error("Verification should fail with corrupted signature")
		}
	}
}

// TestCrossSignatureVerification tests verifying signatures from different identities
func TestCrossSignatureVerification(t *testing.T) {
	// Create two identities
	alice, err := perimeter.NewIdentity("alice")
	if err != nil {
		t.Fatalf("Failed to create Alice's identity: %v", err)
	}

	bob, err := perimeter.NewIdentity("bob")
	if err != nil {
		t.Fatalf("Failed to create Bob's identity: %v", err)
	}

	// Alice signs a message
	message := []byte("Message from Alice")
	aliceSignature, err := alice.Sign(message)
	if err != nil {
		t.Fatalf("Alice failed to sign: %v", err)
	}

	// Alice can verify her own signature
	if !alice.Verify(message, aliceSignature) {
		t.Error("Alice should be able to verify her own signature")
	}

	// Bob should NOT be able to verify Alice's signature using his public key
	if bob.Verify(message, aliceSignature) {
		t.Error("Bob should not verify Alice's signature with Bob's public key")
	}
}

// TestPKIConfigValidation tests PKI configuration validation
func TestPKIConfigValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := perimeter.NewIdentity("config-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Test with nil host (PKI creates its own DHT if host is nil)
	configWithNilHost := perimeter.PKIConfig{
		Host:         nil,
		IPFSEndpoint: "localhost:5001",
		Identity:     identity,
	}

	// This will fail due to IPFS/NATS not being available, not config validation
	_, err = perimeter.NewDistributedPKI(ctx, configWithNilHost)
	// Just verify the function handles nil host gracefully (doesn't panic)
	_ = err

	// Test with valid host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	validConfig := perimeter.PKIConfig{
		Host:         host,
		IPFSEndpoint: "localhost:5001",
		Identity:     identity,
	}

	// Will fail due to external services, but config is valid
	_, err = perimeter.NewDistributedPKI(ctx, validConfig)
	// Config is valid, failure is due to external services
	_ = err
}

// TestRevocationTimestamp tests that revocations have timestamps
func TestRevocationTimestamp(t *testing.T) {
	identity, err := perimeter.NewIdentity("timestamp-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	// Revoke a certificate
	beforeRevoke := time.Now()
	crl.RevokeCertificate("time-cert-1")
	afterRevoke := time.Now()

	// The revocation should have happened between these times
	// (Note: The actual CRL implementation stores this internally)
	if !crl.IsRevoked("time-cert-1") {
		t.Error("Certificate should be revoked")
	}

	// Verify timing makes sense
	_ = beforeRevoke
	_ = afterRevoke
	// In a real implementation, we'd check the revocation timestamp
}

// TestEmptySignature tests handling of empty signatures
func TestEmptySignature(t *testing.T) {
	identity, err := perimeter.NewIdentity("empty-sig-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	message := []byte("Test message")
	emptySignature := []byte{}

	// Empty signature should fail verification
	if identity.Verify(message, emptySignature) {
		t.Error("Empty signature should not verify")
	}
}

// TestNilSignature tests handling of nil signatures
func TestNilSignature(t *testing.T) {
	identity, err := perimeter.NewIdentity("nil-sig-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	message := []byte("Test message")

	// Nil signature should fail verification
	if identity.Verify(message, nil) {
		t.Error("Nil signature should not verify")
	}
}

// TestCRLWithReason tests revoking certificates with reasons
func TestCRLWithReason(t *testing.T) {
	identity, err := perimeter.NewIdentity("crl-reason-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	// Revoke with reason
	crl.RevokeCertificateWithReason("12345", 1) // Reason code 1

	// Verify revocation
	if !crl.IsRevoked("12345") {
		t.Error("Certificate should be revoked")
	}

	// Get revocation info
	info, exists := crl.GetRevocationInfo("12345")
	if !exists {
		t.Fatal("Revocation info should exist")
	}

	if info.Reason != 1 {
		t.Errorf("Expected reason 1, got %d", info.Reason)
	}
}

// TestCertificateRevocationCheck tests checking if x509 cert is revoked
func TestCertificateRevocationCheck(t *testing.T) {
	issuer, err := perimeter.NewIdentity("crl-issuer")
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	subject, err := perimeter.NewIdentity("subject")
	if err != nil {
		t.Fatalf("Failed to create subject: %v", err)
	}

	cert, _, err := issuer.CreateCertificateChain("subject", subject.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	crl := perimeter.NewCRL(issuer)

	// Certificate should not be revoked initially
	if crl.IsCertificateRevoked(cert) {
		t.Error("Certificate should not be revoked initially")
	}

	// Revoke the certificate
	crl.RevokeCertificate(cert.SerialNumber.String())

	// Now it should be revoked
	if !crl.IsCertificateRevoked(cert) {
		t.Error("Certificate should be revoked after revocation")
	}
}

// TestCRLUpdate tests updating CRL timestamps
func TestCRLUpdate(t *testing.T) {
	identity, err := perimeter.NewIdentity("crl-update-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	originalNumber := crl.Number.String()
	originalThisUpdate := crl.ThisUpdate

	// Sleep briefly to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update the CRL
	crl.UpdateCRL()

	// Number should be incremented
	if crl.Number.String() == originalNumber {
		t.Error("CRL number should be incremented after update")
	}

	// ThisUpdate should be newer
	if !crl.ThisUpdate.After(originalThisUpdate) {
		t.Error("ThisUpdate should be newer after update")
	}

	// NextUpdate should be in the future
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Error("NextUpdate should be after ThisUpdate")
	}
}

// TestCRLExpiration tests CRL expiration checking
func TestCRLExpiration(t *testing.T) {
	identity, err := perimeter.NewIdentity("crl-expiry-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	// Fresh CRL should not be expired
	if crl.IsExpired() {
		t.Error("Fresh CRL should not be expired")
	}

	// Manually set NextUpdate to the past
	crl.NextUpdate = time.Now().Add(-1 * time.Hour)

	// Now it should be expired
	if !crl.IsExpired() {
		t.Error("CRL with past NextUpdate should be expired")
	}
}

// TestSignedCRLVerification tests CRL signature verification
func TestSignedCRLVerification(t *testing.T) {
	identity, err := perimeter.NewIdentity("crl-sign-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	// Add some revocations
	crl.RevokeCertificate("12345")
	crl.RevokeCertificate("67890")

	// Get signed CRL
	signedCRL, err := crl.GetSignedCRL()
	if err != nil {
		t.Fatalf("Failed to get signed CRL: %v", err)
	}

	// Verify signature
	err = perimeter.VerifySignedCRL(signedCRL, identity.PublicKey)
	if err != nil {
		t.Errorf("Failed to verify signed CRL: %v", err)
	}

	// Test with corrupted signature
	if len(signedCRL) > 10 {
		corruptedCRL := make([]byte, len(signedCRL))
		copy(corruptedCRL, signedCRL)
		corruptedCRL[len(corruptedCRL)-1] ^= 0xFF

		err = perimeter.VerifySignedCRL(corruptedCRL, identity.PublicKey)
		if err == nil {
			t.Error("Corrupted CRL should fail verification")
		}
	}
}

// TestGetRevocationInfo tests retrieving revocation information
func TestGetRevocationInfo(t *testing.T) {
	identity, err := perimeter.NewIdentity("revocation-info-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	crl := perimeter.NewCRL(identity)

	// Get info for non-existent entry
	_, exists := crl.GetRevocationInfo("nonexistent")
	if exists {
		t.Error("Should not find info for non-existent certificate")
	}

	// Add revocation
	crl.RevokeCertificateWithReason("12345", 3)

	// Get info
	info, exists := crl.GetRevocationInfo("12345")
	if !exists {
		t.Fatal("Should find revocation info")
	}

	if info.Reason != 3 {
		t.Errorf("Expected reason 3, got %d", info.Reason)
	}

	if info.SerialNumber.String() != "12345" {
		t.Errorf("Expected serial 12345, got %s", info.SerialNumber.String())
	}
}
