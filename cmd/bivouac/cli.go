package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/zred/BivouacMesh/pkg/garrison"
	"github.com/zred/BivouacMesh/pkg/perimeter"
)

// CLI represents the command-line interface
type CLI struct {
	consensusService *garrison.ConsensusService
	pki              *perimeter.DistributedPKI
	nodeID           string
}

// NewCLI creates a new CLI
func NewCLI(consensusService *garrison.ConsensusService, pki *perimeter.DistributedPKI, nodeID string) *CLI {
	return &CLI{
		consensusService: consensusService,
		pki:              pki,
		nodeID:           nodeID,
	}
}

// Run starts the CLI
func (cli *CLI) Run() {
	scanner := bufio.NewScanner(os.Stdin)
	
	fmt.Println("\nBivouac Mesh CLI")
	fmt.Println("Type 'help' for available commands")
	fmt.Print("> ")
	
	for scanner.Scan() {
		command := scanner.Text()
		parts := strings.Fields(command)
		
		if len(parts) == 0 {
			fmt.Print("> ")
			continue
		}
		
		switch parts[0] {
		case "help":
			cli.showHelp()
		case "capabilities":
			cli.listCapabilities()
		case "vote":
			if len(parts) < 4 {
				fmt.Println("Usage: vote <node-id> <capability> <level>")
				fmt.Println("Example: vote node-1 ca 1")
			} else {
				nodeID := parts[1]
				capType := perimeter.CapabilityType(parts[2])
				level, err := strconv.Atoi(parts[3])
				if err != nil {
					fmt.Printf("Invalid level: %v\n", err)
					break
				}
				
				cli.voteForCapability(nodeID, capType, level)
			}
		case "check":
			if len(parts) < 3 {
				fmt.Println("Usage: check <node-id> <capability>")
				fmt.Println("Example: check node-1 ca")
			} else {
				nodeID := parts[1]
				capType := perimeter.CapabilityType(parts[2])
				cli.checkCapability(nodeID, capType)
			}
		case "pki":
			cli.showPKI()
		case "peers":
			cli.listPeers()
		case "exit", "quit":
			return
		default:
			fmt.Printf("Unknown command: %s\n", parts[0])
			fmt.Println("Type 'help' for available commands")
		}
		
		fmt.Print("> ")
	}
}

// showHelp displays available commands
func (cli *CLI) showHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  help                 - Show this help message")
	fmt.Println("  capabilities         - List capabilities of this node")
	fmt.Println("  vote <node> <cap> <level> - Vote to grant a capability to a node")
	fmt.Println("  check <node> <cap>   - Check if a node has a capability")
	fmt.Println("  pki                  - Show PKI information")
	fmt.Println("  peers                - List connected peers")
	fmt.Println("  exit, quit           - Exit the CLI")
}

// listCapabilities lists capabilities of this node
func (cli *CLI) listCapabilities() {
	if cli.consensusService == nil {
		fmt.Println("Consensus service not available")
		return
	}
	
	capabilities := cli.consensusService.GetNodeCapabilities(cli.nodeID)
	
	if len(capabilities) == 0 {
		fmt.Println("This node has no capabilities")
		return
	}
	
	fmt.Println("Capabilities for this node:")
	for _, cap := range capabilities {
		fmt.Printf("  - %s (Level %d)\n", cap.Type, cap.Level)
		fmt.Printf("    Granted by: %s\n", strings.Join(cap.GrantedBy, ", "))
		fmt.Printf("    Expires: %s\n", cap.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
}

// voteForCapability votes to grant a capability to a node
func (cli *CLI) voteForCapability(targetNodeID string, capType perimeter.CapabilityType, level int) {
	if cli.consensusService == nil {
		fmt.Println("Consensus service not available")
		return
	}
	
	// In a real implementation, we'd get the target node's public key
	// For this demo, we'll create a dummy key
	dummyKey := make([]byte, 32)
	
	// Use default duration from capability requirements
	req, ok := perimeter.DefaultCapabilityRequirements[capType]
	if !ok {
		fmt.Printf("Unknown capability type: %s\n", capType)
		return
	}
	
	duration := req.ExpirationDuration
	
	// Cast the vote
	vote, err := cli.consensusService.VoteForCapability(
		targetNodeID,
		dummyKey,
		capType,
		level,
		duration)
		
	if err != nil {
		fmt.Printf("Failed to vote: %v\n", err)
		return
	}
	
	fmt.Printf("Vote cast for %s to receive %s capability (Level %d)\n", 
		targetNodeID, capType, level)
	fmt.Printf("Vote expires: %s\n", vote.Expiration.Format("2006-01-02 15:04:05"))
}

// checkCapability checks if a node has a capability
func (cli *CLI) checkCapability(nodeID string, capType perimeter.CapabilityType) {
	if cli.consensusService == nil {
		fmt.Println("Consensus service not available")
		return
	}
	
	hasCapability, level := cli.consensusService.HasCapability(nodeID, capType)
	
	if hasCapability {
		fmt.Printf("Node %s has %s capability (Level %d)\n", nodeID, capType, level)
	} else {
		fmt.Printf("Node %s does not have %s capability\n", nodeID, capType)
	}
}

// showPKI displays PKI information
func (cli *CLI) showPKI() {
	if cli.pki == nil {
		fmt.Println("PKI not available")
		return
	}
	
	if len(cli.pki.RootCAs) == 0 {
		fmt.Println("No trusted root CAs")
	} else {
		fmt.Printf("Trusted root CAs: %d\n", len(cli.pki.RootCAs))
		for _, ca := range cli.pki.RootCAs {
			fmt.Printf("  - %s (expires: %s)\n", 
				ca.Subject.CommonName, 
				ca.NotAfter.Format("2006-01-02"))
		}
	}
}

// listPeers lists connected peers
func (cli *CLI) listPeers() {
	// This would typically connect to the discovery service
	// For the demo, we'll just show a placeholder
	fmt.Println("Connected peers will be listed here")
	fmt.Println("(Feature not implemented in demo)")
}