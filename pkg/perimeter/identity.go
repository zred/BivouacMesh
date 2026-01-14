package perimeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Identity represents a cryptographic identity in the Bivouac Mesh
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Cert       *x509.Certificate
	CertPEM    []byte
}

// NewIdentity creates a new cryptographic identity
func NewIdentity(commonName string) (*Identity, error) {
	// Generate Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(8760 * time.Hour), // 1 year
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
		Cert:       cert,
		CertPEM:    certPEM,
	}, nil
}

// Sign signs a message using the identity's private key
func (id *Identity) Sign(message []byte) ([]byte, error) {
	if id.PrivateKey == nil {
		return nil, errors.New("private key not available")
	}
	return ed25519.Sign(id.PrivateKey, message), nil
}

// Verify verifies a signature using the identity's public key
func (id *Identity) Verify(message, signature []byte) bool {
	return ed25519.Verify(id.PublicKey, message, signature)
}

// CreateCertificateChain creates a certificate signed by this identity
func (id *Identity) CreateCertificateChain(subjectName string, subjectPubKey ed25519.PublicKey) (*x509.Certificate, []byte, error) {
	// Create certificate template for the subject
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: subjectName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(8760 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Sign the certificate with our private key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, id.Cert, subjectPubKey, id.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, certPEM, nil
}

// CRL represents a Certificate Revocation List
type CRL struct {
	Issuer     *Identity
	RevokedIDs map[string]time.Time
}

// NewCRL creates a new Certificate Revocation List
func NewCRL(issuer *Identity) *CRL {
	return &CRL{
		Issuer:     issuer,
		RevokedIDs: make(map[string]time.Time),
	}
}

// RevokeCertificate adds a certificate to the CRL
func (crl *CRL) RevokeCertificate(certSerial string) {
	crl.RevokedIDs[certSerial] = time.Now()
}

// IsRevoked checks if a certificate is revoked
func (crl *CRL) IsRevoked(certSerial string) bool {
	_, revoked := crl.RevokedIDs[certSerial]
	return revoked
}

// GetSignedCRL returns a signed CRL
func (crl *CRL) GetSignedCRL() ([]byte, error) {
	// In a real implementation, this would create a proper x509 CRL
	// For now, we'll just create a simple serialized version
	
	// This is a placeholder - in a production system you would use the proper x509 CRL format
	serialized := []byte(fmt.Sprintf("CRL-ISSUER:%s", crl.Issuer.Cert.Subject.CommonName))
	
	// Sign the serialized CRL with the issuer's private key
	signature, err := crl.Issuer.Sign(serialized)
	if err != nil {
		return nil, err
	}
	
	// Append the signature to the serialized CRL
	signedCRL := append(serialized, signature...)
	
	return signedCRL, nil
}