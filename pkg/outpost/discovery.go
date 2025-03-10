package outpost

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

// DiscoveryService handles peer discovery in the Bivouac Mesh
type DiscoveryService struct {
	Host         host.Host
	DHT          *dht.IpfsDHT
	bootstrappers []peer.AddrInfo
	discoveryTag string
	peersMu      sync.RWMutex
	peers        map[peer.ID]peer.AddrInfo
	ctx          context.Context
	cancel       context.CancelFunc
}

// PeerHandler is a callback function for peer discovery events
type PeerHandler func(peer.AddrInfo)

// NewDiscoveryService creates a new discovery service
func NewDiscoveryService(ctx context.Context, listenAddrs []string, bootstrapPeers []string, discoveryTag string) (*DiscoveryService, error) {
	// Convert string multiaddrs to actual multiaddrs
	maddrs := make([]multiaddr.Multiaddr, 0, len(listenAddrs))
	for _, addr := range listenAddrs {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid multiaddress %s: %w", addr, err)
		}
		maddrs = append(maddrs, ma)
	}

	// Create a libp2p host
	h, err := libp2p.New(
		libp2p.ListenAddrs(maddrs...),
		libp2p.NATPortMap(),
		libp2p.EnableRelay(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Parse bootstrap peers
	bootstrappers := make([]peer.AddrInfo, 0, len(bootstrapPeers))
	for _, addrStr := range bootstrapPeers {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap peer address %s: %w", addrStr, err)
		}
		
		peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to get peer info from address %s: %w", addrStr, err)
		}
		
		bootstrappers = append(bootstrappers, *peerInfo)
	}

	// Create a context for the discovery service
	serviceCtx, cancel := context.WithCancel(ctx)

	// Create the discovery service
	ds := &DiscoveryService{
		Host:         h,
		bootstrappers: bootstrappers,
		discoveryTag: discoveryTag,
		peers:        make(map[peer.ID]peer.AddrInfo),
		ctx:          serviceCtx,
		cancel:       cancel,
	}

	// Create and configure DHT
	kadDHT, err := dht.New(serviceCtx, h)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}
	ds.DHT = kadDHT

	return ds, nil
}

// Start initializes and starts the discovery service
func (ds *DiscoveryService) Start() error {
	// Connect to bootstrap peers
	for _, peerInfo := range ds.bootstrappers {
		if err := ds.Host.Connect(ds.ctx, peerInfo); err != nil {
			// Log the error but continue
			fmt.Printf("Failed to connect to bootstrap peer %s: %v\n", peerInfo.ID, err)
		}
	}

	// Bootstrap the DHT
	if err := ds.DHT.Bootstrap(ds.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Setup mDNS discovery
	mdnsService := mdns.NewMdnsService(ds.Host, ds.discoveryTag, ds)
	if err := mdnsService.Start(); err != nil {
		return fmt.Errorf("failed to start mDNS discovery: %w", err)
	}

	// Start periodic peer discovery
	go ds.discoverPeers()

	return nil
}

// HandlePeerFound is called when a peer is discovered via mDNS
func (ds *DiscoveryService) HandlePeerFound(peerInfo peer.AddrInfo) {
	ds.peersMu.Lock()
	defer ds.peersMu.Unlock()

	if _, ok := ds.peers[peerInfo.ID]; !ok {
		ds.peers[peerInfo.ID] = peerInfo
		// Attempt to connect to the peer
		if err := ds.Host.Connect(ds.ctx, peerInfo); err != nil {
			fmt.Printf("Failed to connect to discovered peer %s: %v\n", peerInfo.ID, err)
		}
	}
}

// discoverPeers periodically looks for new peers in the DHT
func (ds *DiscoveryService) discoverPeers() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ds.ctx.Done():
			return
		case <-ticker.C:
			// Find nearby peers in the DHT
			peers, err := ds.DHT.FindPeers(ds.ctx, ds.discoveryTag)
			if err != nil {
				fmt.Printf("Error finding peers: %v\n", err)
				continue
			}

			// Attempt to connect to discovered peers
			for peerInfo := range peers {
				if peerInfo.ID == ds.Host.ID() {
					continue // Skip ourselves
				}

				ds.peersMu.Lock()
				if _, ok := ds.peers[peerInfo.ID]; !ok {
					ds.peers[peerInfo.ID] = peerInfo
					// Attempt to connect to the peer
					if err := ds.Host.Connect(ds.ctx, peerInfo); err != nil {
						fmt.Printf("Failed to connect to DHT-discovered peer %s: %v\n", peerInfo.ID, err)
					}
				}
				ds.peersMu.Unlock()
			}
		}
	}
}

// GetPeers returns the currently known peers
func (ds *DiscoveryService) GetPeers() []peer.AddrInfo {
	ds.peersMu.RLock()
	defer ds.peersMu.RUnlock()

	peers := make([]peer.AddrInfo, 0, len(ds.peers))
	for _, peer := range ds.peers {
		peers = append(peers, peer)
	}
	return peers
}

// Stop shuts down the discovery service
func (ds *DiscoveryService) Stop() error {
	ds.cancel()
	
	// Close the DHT
	if err := ds.DHT.Close(); err != nil {
		return fmt.Errorf("error closing DHT: %w", err)
	}
	
	// Close the host
	if err := ds.Host.Close(); err != nil {
		return fmt.Errorf("error closing host: %w", err)
	}

	return nil
}