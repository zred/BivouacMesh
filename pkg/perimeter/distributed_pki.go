package perimeter

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/ipfs/go-ipfs-api"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// DistributedPKI implements a hybrid PKI using NATS and DHT/IPFS
type DistributedPKI struct {
	// LibP2P and DHT components
	Host host.Host
	DHT  *dht.IpfsDHT
	
	// IPFS connection
	IPFSShell *shell.Shell
	
	// NATS connection for federation
	NatsConn  *nats.Conn
	JetStream jetstream.JetStream
	
	// Local identity
	Identity *Identity
	
	// Root CA trust store
	RootCAs     []*x509.Certificate
	RootCAsByID map[string]*x509.Certificate
	
	// Context for operations
	ctx context.Context
}

// PKIConfig contains configuration for the distributed PKI
type PKIConfig struct {
	// LibP2P host for DHT operations
	Host host.Host
	
	// IPFS API endpoint
	IPFSEndpoint string
	
	// NATS connection info
	NatsURL     string
	NatsCredsFile string
	
	// Identity information
	Identity *Identity
	
	// Whether this node is a root CA
	IsRootCA bool
}

// NewDistributedPKI creates a new hybrid PKI instance
func NewDistributedPKI(ctx context.Context, config PKIConfig) (*DistributedPKI, error) {
	// Create the DHT if not provided
	var kadDHT *dht.IpfsDHT
	var err error
	
	if config.Host != nil {
		kadDHT, err = dht.New(ctx, config.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to create DHT: %w", err)
		}
	}
	
	// Connect to IPFS
	sh := shell.NewShell(config.IPFSEndpoint)
	if sh == nil {
		return nil, errors.New("failed to connect to IPFS")
	}
	
	// Connect to NATS if URL is provided
	var nc *nats.Conn
	var js jetstream.JetStream
	
	if config.NatsURL != "" {
		opts := []nats.Option{
			nats.Name("Bivouac Mesh PKI"),
			nats.ReconnectWait(2 * time.Second),
			nats.MaxReconnects(-1),
		}
		
		if config.NatsCredsFile != "" {
			opts = append(opts, nats.UserCredentials(config.NatsCredsFile))
		}
		
		nc, err = nats.Connect(config.NatsURL, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to NATS: %w", err)
		}
		
		// Initialize JetStream
		js, err = jetstream.New(nc)
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("failed to create JetStream context: %w", err)
		}
	}
	
	dpki := &DistributedPKI{
		Host:        config.Host,
		DHT:         kadDHT,
		IPFSShell:   sh,
		NatsConn:    nc,
		JetStream:   js,
		Identity:    config.Identity,
		RootCAsByID: make(map[string]*x509.Certificate),
		ctx:         ctx,
	}
	
	// If this is a root CA, publish it to the network
	if config.IsRootCA && config.Identity != nil && config.Identity.Cert != nil {
		err = dpki.PublishRootCA()
		if err != nil {
			// Clean up connections
			if nc != nil {
				nc.Close()
			}
			return nil, fmt.Errorf("failed to publish root CA: %w", err)
		}
	}
	
	// Initialize by fetching known root CAs
	err = dpki.FetchRootCAs()
	if err != nil {
		// Just log the error but continue
		fmt.Printf("Warning: failed to fetch root CAs: %v\n", err)
	}
	
	return dpki, nil
}

// PublishRootCA publishes this node's certificate as a root CA
func (dpki *DistributedPKI) PublishRootCA() error {
	if dpki.Identity == nil || dpki.Identity.Cert == nil {
		return errors.New("no identity or certificate available")
	}
	
	// First, store the certificate in IPFS
	certPEM := dpki.Identity.CertPEM
	
	// Add the certificate to IPFS
	cid, err := dpki.IPFSShell.Add(strings.NewReader(string(certPEM)))
	if err != nil {
		return fmt.Errorf("failed to add certificate to IPFS: %w", err)
	}
	
	// Then, publish the CID to NATS for distribution
	if dpki.NatsConn != nil && dpki.JetStream != nil {
		// Create a stream for root CAs if it doesn't exist
		_, err := dpki.JetStream.CreateStream(dpki.ctx, jetstream.StreamConfig{
			Name:     "ROOTCA",
			Subjects: []string{"pki.rootca.>"},
			Storage:  jetstream.MemoryStorage,
		})
		if err != nil {
			return fmt.Errorf("failed to create root CA stream: %w", err)
		}
		
		// Publish the CID and certificate info
		subject := fmt.Sprintf("pki.rootca.%s", dpki.Identity.Cert.Subject.CommonName)
		data := []byte(fmt.Sprintf("%s|%s|%d", 
			cid, 
			dpki.Identity.Cert.Subject.CommonName,
			dpki.Identity.Cert.NotAfter.Unix(),
		))
		
		_, err = dpki.JetStream.Publish(dpki.ctx, subject, data)
		if err != nil {
			return fmt.Errorf("failed to publish root CA to NATS: %w", err)
		}
	}
	
	// Finally, store a reference in the DHT
	if dpki.Host != nil && dpki.DHT != nil {
		// Use the certificate's subject as the key
		key := fmt.Sprintf("/pki/rootca/%s", dpki.Identity.Cert.Subject.CommonName)
		
		// Store the IPFS CID in the DHT
		err = dpki.DHT.PutValue(dpki.ctx, key, []byte(cid))
		if err != nil {
			return fmt.Errorf("failed to store root CA reference in DHT: %w", err)
		}
	}
	
	return nil
}

// PublishCertificate publishes a node certificate to the network
func (dpki *DistributedPKI) PublishCertificate(cert *x509.Certificate, certPEM []byte) (string, error) {
	if cert == nil || len(certPEM) == 0 {
		return "", errors.New("invalid certificate")
	}
	
	// Add the certificate to IPFS
	cidStr, err := dpki.IPFSShell.Add(strings.NewReader(string(certPEM)))
	if err != nil {
		return "", fmt.Errorf("failed to add certificate to IPFS: %w", err)
	}
	
	// Store a reference in the DHT
	if dpki.Host != nil && dpki.DHT != nil {
		// Use the certificate's subject as the key
		key := fmt.Sprintf("/pki/cert/%s", cert.Subject.CommonName)
		
		// Store the IPFS CID in the DHT
		err = dpki.DHT.PutValue(dpki.ctx, key, []byte(cidStr))
		if err != nil {
			return cidStr, fmt.Errorf("failed to store certificate reference in DHT: %w", err)
		}
	}
	
	return cidStr, nil
}

// FetchCertificate retrieves a certificate from the network
func (dpki *DistributedPKI) FetchCertificate(subjectName string) (*x509.Certificate, []byte, error) {
	// Try to find the certificate reference in the DHT
	key := fmt.Sprintf("/pki/cert/%s", subjectName)
	
	var cidStr string
	var err error
	
	if dpki.DHT != nil {
		// Get the IPFS CID from the DHT
		cidBytes, err := dpki.DHT.GetValue(dpki.ctx, key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find certificate in DHT: %w", err)
		}
		cidStr = string(cidBytes)
	} else {
		// If no DHT, try NATS
		subject := fmt.Sprintf("pki.cert.%s", subjectName)
		
		msg, err := dpki.NatsConn.Request(subject, nil, 5*time.Second)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to request certificate from NATS: %w", err)
		}
		
		parts := strings.Split(string(msg.Data), "|")
		if len(parts) < 1 {
			return nil, nil, errors.New("invalid certificate response from NATS")
		}
		
		cidStr = parts[0]
	}
	
	// Get the certificate from IPFS
	reader, err := dpki.IPFSShell.Cat(cidStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve certificate from IPFS: %w", err)
	}
	
	// Read the PEM data
	pemData := make([]byte, 4096) // Reasonable size for certificates
	n, err := reader.Read(pemData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate data: %w", err)
	}
	
	pemData = pemData[:n]
	
	// Parse the certificate
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to decode PEM data")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	return cert, pemData, nil
}

// FetchRootCAs retrieves all known root CAs from the network
func (dpki *DistributedPKI) FetchRootCAs() error {
	// Use NATS JetStream for root CA discovery
	if dpki.NatsConn != nil && dpki.JetStream != nil {
		// Get the ROOTCA stream
		stream, err := dpki.JetStream.Stream(dpki.ctx, "ROOTCA")
		if err != nil {
			return fmt.Errorf("failed to access root CA stream: %w", err)
		}
		
		// Create a consumer for the stream
		consumer, err := stream.CreateOrUpdateConsumer(dpki.ctx, jetstream.ConsumerConfig{
			Durable:       "rootca-fetch",
			AckPolicy:     jetstream.AckExplicitPolicy,
			DeliverPolicy: jetstream.DeliverAllPolicy,
		})
		if err != nil {
			return fmt.Errorf("failed to create consumer for root CA stream: %w", err)
		}
		
		// Fetch messages
		batch, err := consumer.Fetch(100)
		if err != nil {
			return fmt.Errorf("failed to fetch root CA messages: %w", err)
		}
		
		// Process each message
		for msg := range batch.Messages() {
			// Parse the message data
			parts := strings.Split(string(msg.Data()), "|")
			if len(parts) < 3 {
				msg.Nak()
				continue
			}
			
			cidStr := parts[0]
			subjectName := parts[1]
			
			// Skip if we already have this root CA
			if _, ok := dpki.RootCAsByID[subjectName]; ok {
				msg.Ack()
				continue
			}
			
			// Get the certificate from IPFS
			reader, err := dpki.IPFSShell.Cat(cidStr)
			if err != nil {
				msg.Nak()
				continue
			}
			
			// Read the PEM data
			pemData := make([]byte, 4096)
			n, err := reader.Read(pemData)
			if err != nil {
				msg.Nak()
				continue
			}
			
			pemData = pemData[:n]
			
			// Parse the certificate
			block, _ := pem.Decode(pemData)
			if block == nil || block.Type != "CERTIFICATE" {
				msg.Nak()
				continue
			}
			
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				msg.Nak()
				continue
			}
			
			// Add to our root CA store
			dpki.RootCAs = append(dpki.RootCAs, cert)
			dpki.RootCAsByID[subjectName] = cert
			
			// Acknowledge the message
			msg.Ack()
		}
	} else if dpki.DHT != nil {
		// Use DHT for root CA discovery
		// This is a simplified approach - in a real implementation,
		// you'd need a more robust discovery mechanism
		
		// Look for common root CA names or do a prefix search if supported
		commonNames := []string{"root-ca", "bivouac-root", "mesh-root"}
		
		for _, name := range commonNames {
			key := fmt.Sprintf("/pki/rootca/%s", name)
			
			cidBytes, err := dpki.DHT.GetValue(dpki.ctx, key)
			if err != nil {
				continue
			}
			
			// Get the certificate from IPFS
			reader, err := dpki.IPFSShell.Cat(string(cidBytes))
			if err != nil {
				continue
			}
			
			// Read the PEM data
			pemData := make([]byte, 4096)
			n, err := reader.Read(pemData)
			if err != nil {
				continue
			}
			
			pemData = pemData[:n]
			
			// Parse the certificate
			block, _ := pem.Decode(pemData)
			if block == nil || block.Type != "CERTIFICATE" {
				continue
			}
			
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			
			// Add to our root CA store
			dpki.RootCAs = append(dpki.RootCAs, cert)
			dpki.RootCAsByID[cert.Subject.CommonName] = cert
		}
	}
	
	return nil
}

// PublishCRL publishes a certificate revocation list
func (dpki *DistributedPKI) PublishCRL(crl *CRL) (string, error) {
	// Get the signed CRL
	signedCRL, err := crl.GetSignedCRL()
	if err != nil {
		return "", fmt.Errorf("failed to get signed CRL: %w", err)
	}
	
	// Add the CRL to IPFS
	cidStr, err := dpki.IPFSShell.Add(strings.NewReader(string(signedCRL)))
	if err != nil {
		return "", fmt.Errorf("failed to add CRL to IPFS: %w", err)
	}
	
	// Publish to NATS for immediate notification
	if dpki.NatsConn != nil && dpki.JetStream != nil {
		// Create a stream for CRLs if it doesn't exist
		_, err := dpki.JetStream.CreateStream(dpki.ctx, jetstream.StreamConfig{
			Name:     "CRL",
			Subjects: []string{"pki.crl.>"},
			Storage:  jetstream.MemoryStorage,
		})
		if err != nil {
			return cidStr, fmt.Errorf("failed to create CRL stream: %w", err)
		}
		
		// Publish the CID and issuer info
		subject := fmt.Sprintf("pki.crl.%s", crl.Issuer.Cert.Subject.CommonName)
		data := []byte(fmt.Sprintf("%s|%s|%d", 
			cidStr, 
			crl.Issuer.Cert.Subject.CommonName,
			time.Now().Unix(),
		))
		
		_, err = dpki.JetStream.Publish(dpki.ctx, subject, data)
		if err != nil {
			return cidStr, fmt.Errorf("failed to publish CRL to NATS: %w", err)
		}
	}
	
	// Store in DHT for discovery
	if dpki.DHT != nil {
		key := fmt.Sprintf("/pki/crl/%s", crl.Issuer.Cert.Subject.CommonName)
		err = dpki.DHT.PutValue(dpki.ctx, key, []byte(cidStr))
		if err != nil {
			return cidStr, fmt.Errorf("failed to store CRL reference in DHT: %w", err)
		}
	}
	
	return cidStr, nil
}

// CheckRevocation checks if a certificate has been revoked
func (dpki *DistributedPKI) CheckRevocation(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, errors.New("invalid certificate")
	}
	
	// Get the issuer name
	issuerName := cert.Issuer.CommonName
	
	// Try to get the CRL from the DHT
	key := fmt.Sprintf("/pki/crl/%s", issuerName)
	
	var cidStr string
	
	if dpki.DHT != nil {
		cidBytes, err := dpki.DHT.GetValue(dpki.ctx, key)
		if err != nil {
			// Try NATS if DHT fails
			if dpki.NatsConn != nil {
				subject := fmt.Sprintf("pki.crl.%s", issuerName)
				msg, err := dpki.NatsConn.Request(subject, nil, 5*time.Second)
				if err != nil {
					return false, fmt.Errorf("failed to find CRL for issuer %s: %w", issuerName, err)
				}
				
				parts := strings.Split(string(msg.Data), "|")
				if len(parts) < 1 {
					return false, errors.New("invalid CRL response format")
				}
				
				cidStr = parts[0]
			} else {
				return false, fmt.Errorf("failed to find CRL for issuer %s: %w", issuerName, err)
			}
		} else {
			cidStr = string(cidBytes)
		}
	} else if dpki.NatsConn != nil {
		// Use NATS directly if no DHT
		subject := fmt.Sprintf("pki.crl.%s", issuerName)
		msg, err := dpki.NatsConn.Request(subject, nil, 5*time.Second)
		if err != nil {
			return false, fmt.Errorf("failed to find CRL for issuer %s: %w", issuerName, err)
		}
		
		parts := strings.Split(string(msg.Data), "|")
		if len(parts) < 1 {
			return false, errors.New("invalid CRL response format")
		}
		
		cidStr = parts[0]
	} else {
		return false, errors.New("no DHT or NATS available to check revocation")
	}
	
	// Get the CRL from IPFS
	reader, err := dpki.IPFSShell.Cat(cidStr)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve CRL from IPFS: %w", err)
	}
	
	// Read the CRL data
	crlData := make([]byte, 8192) // CRLs can be larger
	n, err := reader.Read(crlData)
	if err != nil {
		return false, fmt.Errorf("failed to read CRL data: %w", err)
	}
	
	crlData = crlData[:n]
	
	// In a real implementation, we'd parse the CRL and check if this cert is revoked
	// For this simplified version, we'll just check if the serial number is mentioned
	serialStr := fmt.Sprintf("%d", cert.SerialNumber)
	return strings.Contains(string(crlData), serialStr), nil
}

// CreateAndSignCertificate creates a new certificate and signs it
func (dpki *DistributedPKI) CreateAndSignCertificate(subjectName string, subjectPubKey ed25519.PublicKey) (*x509.Certificate, []byte, error) {
	if dpki.Identity == nil {
		return nil, nil, errors.New("no identity available to sign certificate")
	}
	
	// Create and sign the certificate
	cert, certPEM, err := dpki.Identity.CreateCertificateChain(subjectName, subjectPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	
	// Publish the certificate to the network
	_, err = dpki.PublishCertificate(cert, certPEM)
	if err != nil {
		return cert, certPEM, fmt.Errorf("certificate created but failed to publish: %w", err)
	}
	
	return cert, certPEM, nil
}

// VerifyCertificateChain verifies a certificate against trusted roots
func (dpki *DistributedPKI) VerifyCertificateChain(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("invalid certificate")
	}
	
	// Check if the certificate has been revoked
	revoked, err := dpki.CheckRevocation(cert)
	if err != nil {
		return fmt.Errorf("failed to check revocation status: %w", err)
	}
	
	if revoked {
		return errors.New("certificate has been revoked")
	}
	
	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New("certificate not yet valid")
	}
	
	if now.After(cert.NotAfter) {
		return errors.New("certificate has expired")
	}
	
	// For self-signed certificates
	if cert.Issuer.CommonName == cert.Subject.CommonName {
		// Check if it's a trusted root
		for _, root := range dpki.RootCAs {
			if root.Subject.CommonName == cert.Subject.CommonName {
				// In a real implementation, we'd properly compare certificates
				return nil
			}
		}
		return errors.New("self-signed certificate not in trusted roots")
	}
	
	// For certificates signed by another CA
	issuerName := cert.Issuer.CommonName
	
	// Check if we have the issuer in our root store
	_, ok := dpki.RootCAsByID[issuerName]
	if ok {
		// In a real implementation, we'd properly verify the signature
		return nil
	}
	
	// Fetch the issuer certificate from the network
	issuerCert, _, err := dpki.FetchCertificate(issuerName)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer certificate: %w", err)
	}
	
	// Recursively verify the issuer's certificate
	err = dpki.VerifyCertificateChain(issuerCert)
	if err != nil {
		return fmt.Errorf("issuer certificate verification failed: %w", err)
	}
	
	// In a real implementation, we'd verify that the issuer properly signed this certificate
	
	return nil
}

// Close cleans up the PKI resources
func (dpki *DistributedPKI) Close() error {
	var errors []string
	
	// Close NATS connection
	if dpki.NatsConn != nil {
		dpki.NatsConn.Close()
	}
	
	// Return combined errors if any
	if len(errors) > 0 {
		return fmt.Errorf("errors closing PKI: %s", strings.Join(errors, "; "))
	}
	
	return nil
}