package main

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/zred/BivouacMesh/pkg/outpost"
	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// initPKI initializes the distributed PKI system
func initPKI(ctx context.Context, nodeName string, identity *perimeter.Identity, 
             discovery *outpost.DiscoveryService, natsURL string, isRootCA bool) (*perimeter.DistributedPKI, error) {
	
	fmt.Println("Initializing distributed PKI...")
	
	// Set default IPFS API endpoint
	ipfsEndpoint := "localhost:5001" // Default IPFS API
	
	// Configure the PKI
	pkiConfig := perimeter.PKIConfig{
		Host:         discovery.Host,
		IPFSEndpoint: ipfsEndpoint,
		NatsURL:      natsURL,
		Identity:     identity,
		IsRootCA:     isRootCA,
	}
	
	// Create the PKI
	pki, err := perimeter.NewDistributedPKI(ctx, pkiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKI: %w", err)
	}
	
	fmt.Println("PKI initialized successfully")
	
	// If this is a root CA, inform the user
	if isRootCA {
		fmt.Println("This node is operating as a Root Certificate Authority")
	}
	
	// Report trusted roots
	if len(pki.RootCAs) > 0 {
		fmt.Printf("Trusted root CAs: %d\n", len(pki.RootCAs))
		for _, ca := range pki.RootCAs {
			fmt.Printf("  - %s (expires: %s)\n", ca.Subject.CommonName, ca.NotAfter.Format("2006-01-02"))
		}
	} else {
		fmt.Println("No trusted root CAs found in the network")
		
		// If we're a root CA, we should trust ourselves
		if isRootCA {
			fmt.Println("This node is a Root CA but not yet in the trust store. Adding self...")
			pki.RootCAs = append(pki.RootCAs, identity.Cert)
			pki.RootCAsByID[identity.Cert.Subject.CommonName] = identity.Cert
		}
	}
	
	return pki, nil
}

// createChildIdentity creates a child identity signed by this node
func createChildIdentity(pki *perimeter.DistributedPKI, childName string) (*perimeter.Identity, error) {
	// Create a new key pair for the child
	childIdentity, err := perimeter.NewIdentity(childName)
	if err != nil {
		return nil, fmt.Errorf("failed to create child identity: %w", err)
	}
	
	// Sign the child's certificate
	childCert, childCertPEM, err := pki.CreateAndSignCertificate(childName, childIdentity.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign child certificate: %w", err)
	}
	
	// Update the child's certificate with the signed one
	childIdentity.Cert = childCert
	childIdentity.CertPEM = childCertPEM
	
	return childIdentity, nil
}

// verifyPeerIdentity verifies a peer's identity using the PKI
func verifyPeerIdentity(pki *perimeter.DistributedPKI, peerCert *x509.Certificate) error {
	// Check if the peer's certificate has been revoked
	revoked, err := pki.CheckRevocation(peerCert)
	if err != nil {
		return fmt.Errorf("failed to check if peer certificate is revoked: %w", err)
	}
	
	if revoked {
		return fmt.Errorf("peer certificate has been revoked")
	}
	
	// Verify the peer's certificate chain
	err = pki.VerifyCertificateChain(peerCert)
	if err != nil {
		return fmt.Errorf("failed to verify peer certificate chain: %w", err)
	}
	
	return nil
}

// setupPKIHandlers sets up message handlers for PKI-related requests
func setupPKIHandlers(ctx context.Context, nc *nats.Conn, pki *perimeter.DistributedPKI) error {
	if nc == nil {
		return fmt.Errorf("NATS connection not available")
	}
	
	// Handle certificate requests
	_, err := nc.Subscribe("pki.cert.request", func(msg *nats.Msg) {
		// Parse the request (assuming it contains a subject name)
		subjectName := string(msg.Data)

		// Fetch the certificate
		_, certPEM, err := pki.FetchCertificate(subjectName)
		if err != nil {
			// Reply with error
			nc.Publish(msg.Reply, []byte("ERROR: "+err.Error()))
			return
		}

		// Reply with the certificate PEM
		nc.Publish(msg.Reply, certPEM)
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to certificate requests: %w", err)
	}
	
	// Handle CRL requests
	_, err = nc.Subscribe("pki.crl.request", func(msg *nats.Msg) {
		// Parse the request (assuming it contains an issuer name)
		issuerName := string(msg.Data)
		
		// Try to get the CRL from the DHT
		key := fmt.Sprintf("/pki/crl/%s", issuerName)

		cidBytes, err := pki.DHT.GetValue(ctx, key)
		if err != nil {
			// Reply with error
			nc.Publish(msg.Reply, []byte("ERROR: "+err.Error()))
			return
		}
		
		// Get the CRL from IPFS
		reader, err := pki.IPFSShell.Cat(string(cidBytes))
		if err != nil {
			// Reply with error
			nc.Publish(msg.Reply, []byte("ERROR: "+err.Error()))
			return
		}
		
		// Read the CRL data
		crlData := make([]byte, 8192)
		n, err := reader.Read(crlData)
		if err != nil {
			// Reply with error
			nc.Publish(msg.Reply, []byte("ERROR: "+err.Error()))
			return
		}
		
		// Reply with the CRL data
		nc.Publish(msg.Reply, crlData[:n])
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to CRL requests: %w", err)
	}
	
	return nil
}