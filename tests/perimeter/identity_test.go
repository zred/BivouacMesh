package perimeter_test

import (
	"testing"

	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// Test key generation functionality
func TestKeyGeneration(t *testing.T) {
	// Create a new identity
	identity, err := perimeter.NewIdentity("test-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}
	
	// Verify that private key is generated
	if identity.PrivateKey == nil {
		t.Error("Private key not generated")
	}
	
	// Verify that public key is generated
	if identity.PublicKey == nil {
		t.Error("Public key not generated")
	}
	
	// Verify certificate generation
	if identity.Cert == nil {
		t.Error("Certificate not generated")
	}
	
	// Verify certificate subject matches
	if identity.Cert.Subject.CommonName != "test-node" {
		t.Errorf("Certificate subject mismatch: expected 'test-node', got '%s'", identity.Cert.Subject.CommonName)
	}
}

// Test certificate validation and chaining
func TestCertificateValidation(t *testing.T) {
	// Create a root identity
	rootIdentity, err := perimeter.NewIdentity("root-ca")
	if err != nil {
		t.Fatalf("Failed to create root identity: %v", err)
	}
	
	// Create another identity for signing
	subjectIdentity, err := perimeter.NewIdentity("subject-node")
	if err != nil {
		t.Fatalf("Failed to create subject identity: %v", err)
	}
	
	// Create a certificate chain
	subjectCert, subjectCertPEM, err := rootIdentity.CreateCertificateChain(
		"subject-node",
		subjectIdentity.PublicKey,
	)
	
	if err != nil {
		t.Fatalf("Failed to create certificate chain: %v", err)
	}
	
	// Verify the certificate was created
	if subjectCert == nil {
		t.Error("Subject certificate is nil")
	}
	
	// Verify the certificate PEM was created
	if len(subjectCertPEM) == 0 {
		t.Error("Subject certificate PEM is empty")
	}
	
	// Verify certificate subject
	if subjectCert.Subject.CommonName != "subject-node" {
		t.Errorf("Certificate subject mismatch: expected 'subject-node', got '%s'", subjectCert.Subject.CommonName)
	}
	
	// Verify certificate issuer
	if subjectCert.Issuer.CommonName != "root-ca" {
		t.Errorf("Certificate issuer mismatch: expected 'root-ca', got '%s'", subjectCert.Issuer.CommonName)
	}
}

// Test signing and verification
func TestSigningAndVerification(t *testing.T) {
	// Create a new identity
	identity, err := perimeter.NewIdentity("signing-node")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}
	
	// Create a message to sign
	message := []byte("Hello, Bivouac Mesh!")
	
	// Sign the message
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	
	// Verify the signature
	if !identity.Verify(message, signature) {
		t.Error("Signature verification failed")
	}
	
	// Verify that modifying the message causes verification to fail
	modifiedMessage := []byte("Hello, Modified Message!")
	if identity.Verify(modifiedMessage, signature) {
		t.Error("Verification succeeded with modified message, should have failed")
	}
	
	// Verify that modifying the signature causes verification to fail
	if len(signature) > 0 {
		modifiedSignature := make([]byte, len(signature))
		copy(modifiedSignature, signature)
		modifiedSignature[0] = modifiedSignature[0] ^ 0xFF // Flip some bits
		
		if identity.Verify(message, modifiedSignature) {
			t.Error("Verification succeeded with modified signature, should have failed")
		}
	}
}

// Test CRL revocation
func TestCRLRevocation(t *testing.T) {
	// Create a root identity
	rootIdentity, err := perimeter.NewIdentity("revocation-ca")
	if err != nil {
		t.Fatalf("Failed to create root identity: %v", err)
	}
	
	// Create a CRL
	crl := perimeter.NewCRL(rootIdentity)
	
	// Certificate serial to revoke
	certSerial := "1234"
	
	// Verify the certificate is not revoked initially
	if crl.IsRevoked(certSerial) {
		t.Error("Certificate is marked as revoked before revocation")
	}
	
	// Revoke the certificate
	crl.RevokeCertificate(certSerial)
	
	// Verify the certificate is now revoked
	if !crl.IsRevoked(certSerial) {
		t.Error("Certificate is not marked as revoked after revocation")
	}
	
	// Generate a signed CRL
	signedCRL, err := crl.GetSignedCRL()
	if err != nil {
		t.Fatalf("Failed to generate signed CRL: %v", err)
	}
	
	// Verify the signed CRL is not empty
	if len(signedCRL) == 0 {
		t.Error("Signed CRL is empty")
	}
}