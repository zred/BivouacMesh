package perimeter_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// TestValidatePublicKey tests public key validation
func TestValidatePublicKey(t *testing.T) {
	// Test with valid key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	err = perimeter.ValidatePublicKey(pub)
	if err != nil {
		t.Errorf("Valid public key should pass validation: %v", err)
	}

	// Test with invalid size (too short)
	shortKey := make([]byte, 16)
	err = perimeter.ValidatePublicKey(shortKey)
	if err == nil {
		t.Error("Short public key should fail validation")
	}

	// Test with all-zero key
	zeroKey := make([]byte, ed25519.PublicKeySize)
	err = perimeter.ValidatePublicKey(zeroKey)
	if err == nil {
		t.Error("All-zero public key should fail validation")
	}

	// Test with nil key
	err = perimeter.ValidatePublicKey(nil)
	if err == nil {
		t.Error("Nil public key should fail validation")
	}
}

// TestValidatePrivateKey tests private key validation
func TestValidatePrivateKey(t *testing.T) {
	// Test with valid key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_ = pub // Keep for potential future use

	err = perimeter.ValidatePrivateKey(priv)
	if err != nil {
		t.Errorf("Valid private key should pass validation: %v", err)
	}

	// Test with invalid size
	shortKey := make([]byte, 32)
	err = perimeter.ValidatePrivateKey(shortKey)
	if err == nil {
		t.Error("Short private key should fail validation")
	}

	// Test with all-zero key
	zeroKey := make([]byte, ed25519.PrivateKeySize)
	err = perimeter.ValidatePrivateKey(zeroKey)
	if err == nil {
		t.Error("All-zero private key should fail validation")
	}
}

// TestValidateCertificate tests certificate validation
func TestValidateCertificate(t *testing.T) {
	// Create valid identity
	identity, err := perimeter.NewIdentity("test-cert-validation")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Test with valid certificate
	err = perimeter.ValidateCertificate(identity.Cert)
	if err != nil {
		t.Errorf("Valid certificate should pass validation: %v", err)
	}

	// Test with nil certificate
	err = perimeter.ValidateCertificate(nil)
	if err == nil {
		t.Error("Nil certificate should fail validation")
	}

	// Test with expired certificate
	expiredCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "expired-cert",
		},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	err = perimeter.ValidateCertificate(expiredCert)
	if err == nil {
		t.Error("Expired certificate should fail validation")
	}

	// Test with not-yet-valid certificate
	futureCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "future-cert",
		},
		NotBefore: time.Now().Add(24 * time.Hour), // Future
		NotAfter:  time.Now().Add(48 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	err = perimeter.ValidateCertificate(futureCert)
	if err == nil {
		t.Error("Not-yet-valid certificate should fail validation")
	}

	// Test certificate without CommonName
	noNameCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	err = perimeter.ValidateCertificate(noNameCert)
	if err == nil {
		t.Error("Certificate without CommonName should fail validation")
	}

	// Test certificate without digital signature usage
	noSigCert := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName: "no-sig-cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment, // No digital signature
	}

	err = perimeter.ValidateCertificate(noSigCert)
	if err == nil {
		t.Error("Certificate without digital signature usage should fail validation")
	}
}

// TestValidateSignature tests signature validation
func TestValidateSignature(t *testing.T) {
	// Generate key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("Test message for signature validation")
	signature := ed25519.Sign(priv, message)

	// Test valid signature
	err = perimeter.ValidateSignature(pub, message, signature)
	if err != nil {
		t.Errorf("Valid signature should pass validation: %v", err)
	}

	// Test with invalid signature
	invalidSig := make([]byte, ed25519.SignatureSize)
	err = perimeter.ValidateSignature(pub, message, invalidSig)
	if err == nil {
		t.Error("Invalid signature should fail validation")
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	err = perimeter.ValidateSignature(pub, wrongMessage, signature)
	if err == nil {
		t.Error("Signature with wrong message should fail validation")
	}

	// Test with empty message
	err = perimeter.ValidateSignature(pub, []byte{}, signature)
	if err == nil {
		t.Error("Empty message should fail validation")
	}

	// Test with wrong size signature
	shortSig := make([]byte, 32)
	err = perimeter.ValidateSignature(pub, message, shortSig)
	if err == nil {
		t.Error("Short signature should fail validation")
	}

	// Test with all-zero public key
	zeroKey := make([]byte, ed25519.PublicKeySize)
	err = perimeter.ValidateSignature(zeroKey, message, signature)
	if err == nil {
		t.Error("All-zero public key should fail validation")
	}
}

// TestSignWithValidation tests that Sign method validates inputs
func TestSignWithValidation(t *testing.T) {
	identity, err := perimeter.NewIdentity("sign-validation-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Test signing empty message
	_, err = identity.Sign([]byte{})
	if err == nil {
		t.Error("Sign should reject empty message")
	}

	// Test normal signing
	message := []byte("Valid message")
	sig, err := identity.Sign(message)
	if err != nil {
		t.Errorf("Sign failed with valid message: %v", err)
	}

	// Verify the signature
	if !identity.Verify(message, sig) {
		t.Error("Signature verification failed")
	}
}

// TestVerifyWithValidation tests that Verify method validates inputs
func TestVerifyWithValidation(t *testing.T) {
	identity, err := perimeter.NewIdentity("verify-validation-test")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	message := []byte("Test message")
	sig, _ := identity.Sign(message)

	// Test verify with empty message
	if identity.Verify([]byte{}, sig) {
		t.Error("Verify should reject empty message")
	}

	// Test verify with wrong signature size
	shortSig := make([]byte, 32)
	if identity.Verify(message, shortSig) {
		t.Error("Verify should reject short signature")
	}

	// Test verify with empty signature
	if identity.Verify(message, []byte{}) {
		t.Error("Verify should reject empty signature")
	}
}

// TestRandomSerialNumbers tests that serial numbers are cryptographically random
func TestRandomSerialNumbers(t *testing.T) {
	// Create multiple identities and verify serial numbers are different
	serials := make(map[string]bool)

	for i := 0; i < 10; i++ {
		identity, err := perimeter.NewIdentity("serial-test")
		if err != nil {
			t.Fatalf("Failed to create identity: %v", err)
		}

		serialStr := identity.Cert.SerialNumber.String()
		if serials[serialStr] {
			t.Errorf("Duplicate serial number found: %s", serialStr)
		}
		serials[serialStr] = true

		// Verify serial number is non-zero
		if identity.Cert.SerialNumber.Cmp(big.NewInt(0)) == 0 {
			t.Error("Serial number should not be zero")
		}

		// Verify serial number is reasonably large (more than a simple counter)
		if identity.Cert.SerialNumber.Cmp(big.NewInt(1000000)) < 0 {
			t.Error("Serial number seems too small, may not be cryptographically random")
		}
	}
}

// TestCertificateChainStructure tests creating a certificate chain structure
func TestCertificateChainStructure(t *testing.T) {
	// Create root CA
	rootCA, err := perimeter.NewIdentity("root-ca")
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	// Create intermediate CA
	intermediateCA, err := perimeter.NewIdentity("intermediate-ca")
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	// Create leaf certificate
	leaf, err := perimeter.NewIdentity("leaf-cert")
	if err != nil {
		t.Fatalf("Failed to create leaf: %v", err)
	}

	// Build chain: leaf -> intermediate -> root
	certs := []*x509.Certificate{leaf.Cert, intermediateCA.Cert, rootCA.Cert}
	rootCAs := []*x509.Certificate{rootCA.Cert}

	chain := perimeter.NewCertificateChain(certs, rootCAs)

	if chain.Length() != 3 {
		t.Errorf("Expected chain length 3, got %d", chain.Length())
	}

	leafCert := chain.GetLeafCertificate()
	if leafCert.Subject.CommonName != "leaf-cert" {
		t.Errorf("Expected leaf cert CommonName 'leaf-cert', got '%s'", leafCert.Subject.CommonName)
	}

	rootCert := chain.GetRootCertificate()
	if rootCert.Subject.CommonName != "root-ca" {
		t.Errorf("Expected root cert CommonName 'root-ca', got '%s'", rootCert.Subject.CommonName)
	}
}

// TestSelfSignedCertificateChain tests validation of self-signed certificate
func TestSelfSignedCertificateChain(t *testing.T) {
	identity, err := perimeter.NewIdentity("self-signed")
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Create chain with just the self-signed cert
	chain := perimeter.NewCertificateChain([]*x509.Certificate{identity.Cert}, nil)

	// Should validate successfully
	err = chain.Verify()
	if err != nil {
		t.Errorf("Self-signed certificate should validate: %v", err)
	}
}

// TestEmptyCertificateChain tests that empty chains are rejected
func TestEmptyCertificateChain(t *testing.T) {
	chain := perimeter.NewCertificateChain([]*x509.Certificate{}, nil)

	err := chain.Verify()
	if err == nil {
		t.Error("Empty certificate chain should fail validation")
	}
}

// TestCertificateChainWithExpiredCert tests that expired certs fail
func TestCertificateChainWithExpiredCert(t *testing.T) {
	// Create expired certificate
	expiredCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "expired",
		},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	chain := perimeter.NewCertificateChain([]*x509.Certificate{expiredCert}, nil)

	err := chain.Verify()
	if err == nil {
		t.Error("Chain with expired certificate should fail validation")
	}
}

// TestCertificateChainLength tests the Length method
func TestCertificateChainLength(t *testing.T) {
	id1, _ := perimeter.NewIdentity("cert1")
	id2, _ := perimeter.NewIdentity("cert2")
	id3, _ := perimeter.NewIdentity("cert3")

	chain := perimeter.NewCertificateChain(
		[]*x509.Certificate{id1.Cert, id2.Cert, id3.Cert},
		nil,
	)

	if chain.Length() != 3 {
		t.Errorf("Expected length 3, got %d", chain.Length())
	}

	// Test empty chain
	emptyChain := perimeter.NewCertificateChain([]*x509.Certificate{}, nil)
	if emptyChain.Length() != 0 {
		t.Errorf("Expected length 0 for empty chain, got %d", emptyChain.Length())
	}
}

// TestGetLeafAndRootCertificates tests getter methods
func TestGetLeafAndRootCertificates(t *testing.T) {
	leaf, _ := perimeter.NewIdentity("leaf")
	intermediate, _ := perimeter.NewIdentity("intermediate")
	root, _ := perimeter.NewIdentity("root")

	chain := perimeter.NewCertificateChain(
		[]*x509.Certificate{leaf.Cert, intermediate.Cert, root.Cert},
		[]*x509.Certificate{root.Cert},
	)

	leafCert := chain.GetLeafCertificate()
	if leafCert == nil {
		t.Fatal("GetLeafCertificate returned nil")
	}
	if leafCert.Subject.CommonName != "leaf" {
		t.Errorf("Expected leaf CommonName 'leaf', got '%s'", leafCert.Subject.CommonName)
	}

	rootCert := chain.GetRootCertificate()
	if rootCert == nil {
		t.Fatal("GetRootCertificate returned nil")
	}
	if rootCert.Subject.CommonName != "root" {
		t.Errorf("Expected root CommonName 'root', got '%s'", rootCert.Subject.CommonName)
	}

	// Test with empty chain
	emptyChain := perimeter.NewCertificateChain([]*x509.Certificate{}, nil)
	if emptyChain.GetLeafCertificate() != nil {
		t.Error("Empty chain should return nil for leaf certificate")
	}
	if emptyChain.GetRootCertificate() != nil {
		t.Error("Empty chain should return nil for root certificate")
	}
}
