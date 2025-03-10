package garrison

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/yourusername/bivouac-mesh/pkg/perimeter"
	"github.com/yourusername/bivouac-mesh/pkg/signals"
)

// FederationNode represents a high-trust federation node in the Bivouac Mesh
type FederationNode struct {
	Identity        *perimeter.Identity
	NatsConn        *nats.Conn
	JetStream       jetstream.JetStream
	streams         map[string]jetstream.Stream
	subscriptions   map[string]jetstream.Consumer
	accessPolicies  map[string]AccessPolicy
	policyMutex     sync.RWMutex
	messageCh       chan *signals.Message
	ctx             context.Context
	cancel          context.CancelFunc
}

// AccessPolicy defines who can access a specific stream or resource
type AccessPolicy struct {
	ResourceName     string
	AllowedIdentities []string
	RequiredSigs     int // For multi-signature schemes
}

// FederationConfig holds configuration for a federation node
type FederationConfig struct {
	NatsURL         string
	NatsCredentials string
	Identity        *perimeter.Identity
	StreamConfigs   []StreamConfig
}

// StreamConfig defines how to configure a NATS JetStream
type StreamConfig struct {
	Name          string
	Subjects      []string
	MaxAge        time.Duration
	AccessPolicy  AccessPolicy
}

// NewFederationNode creates a new federation node
func NewFederationNode(ctx context.Context, config FederationConfig) (*FederationNode, error) {
	// Connect to NATS server
	opts := []nats.Option{
		nats.Name("Bivouac Mesh Federation Node"),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1),
	}
	
	// Add credentials if provided
	if config.NatsCredentials != "" {
		opts = append(opts, nats.UserCredentials(config.NatsCredentials))
	}
	
	// Connect to NATS
	nc, err := nats.Connect(config.NatsURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}
	
	// Create JetStream context
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}
	
	// Create a context for the federation node
	nodeCtx, cancel := context.WithCancel(ctx)
	
	// Create the federation node
	fn := &FederationNode{
		Identity:        config.Identity,
		NatsConn:        nc,
		JetStream:       js,
		streams:         make(map[string]jetstream.Stream),
		subscriptions:   make(map[string]jetstream.Consumer),
		accessPolicies:  make(map[string]AccessPolicy),
		messageCh:       make(chan *signals.Message, 1000),
		ctx:             nodeCtx,
		cancel:          cancel,
	}
	
	// Setup streams
	for _, streamConfig := range config.StreamConfigs {
		if err := fn.createStream(streamConfig); err != nil {
			cancel()
			nc.Close()
			return nil, fmt.Errorf("failed to create stream %s: %w", streamConfig.Name, err)
		}
		
		// Store access policy
		fn.policyMutex.Lock()
		fn.accessPolicies[streamConfig.Name] = streamConfig.AccessPolicy
		fn.policyMutex.Unlock()
	}
	
	return fn, nil
}

// createStream creates a new JetStream
func (fn *FederationNode) createStream(config StreamConfig) error {
	// Configure the stream
	streamConfig := jetstream.StreamConfig{
		Name:     config.Name,
		Subjects: config.Subjects,
		MaxAge:   config.MaxAge,
		Storage:  jetstream.MemoryStorage,
	}
	
	// Create the stream
	stream, err := fn.JetStream.CreateOrUpdateStream(fn.ctx, streamConfig)
	if err != nil {
		return err
	}
	
	fn.streams[config.Name] = stream
	return nil
}

// SubscribeToStream subscribes to a stream
func (fn *FederationNode) SubscribeToStream(streamName string, consumerName string) error {
	stream, ok := fn.streams[streamName]
	if !ok {
		return fmt.Errorf("stream %s not found", streamName)
	}
	
	// Create a consumer
	consumerConfig := jetstream.ConsumerConfig{
		Durable:   consumerName,
		AckPolicy: jetstream.AckExplicitPolicy,
	}
	
	consumer, err := stream.CreateOrUpdateConsumer(fn.ctx, consumerConfig)
	if err != nil {
		return fmt.Errorf("failed to create consumer: %w", err)
	}
	
	fn.subscriptions[consumerName] = consumer
	
	// Start consuming messages
	go fn.consumeMessages(consumer)
	
	return nil
}

// consumeMessages processes messages from a NATS consumer
func (fn *FederationNode) consumeMessages(consumer jetstream.Consumer) {
	for {
		select {
		case <-fn.ctx.Done():
			return
		default:
			// Fetch messages
			messages, err := consumer.Fetch(10, jetstream.FetchMaxWait(1*time.Second))
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					// No messages available, just continue
					continue
				}
				fmt.Printf("Error fetching messages: %v\n", err)
				time.Sleep(1 * time.Second)
				continue
			}
			
			// Process each message
			for message := range messages.Messages() {
				// Convert NATS message to signals.Message
				msg, err := fn.convertNatsMessage(message.Data())
				if err != nil {
					fmt.Printf("Error converting message: %v\n", err)
					message.Nak()
					continue
				}
				
				// Validate the message
				if err := msg.Validate(); err != nil {
					fmt.Printf("Message validation failed: %v\n", err)
					message.Nak()
					continue
				}
				
				// Check access policy
				if !fn.checkAccessPolicy(message.Subject(), msg) {
					fmt.Printf("Access denied for message from %s\n", msg.Sender)
					message.Nak()
					continue
				}
				
				// Forward the message to the channel
				fn.messageCh <- msg
				
				// Acknowledge the message
				if err := message.Ack(); err != nil {
					fmt.Printf("Error acknowledging message: %v\n", err)
				}
			}
		}
	}
}

// convertNatsMessage converts a NATS message to a signals.Message
func (fn *FederationNode) convertNatsMessage(data []byte) (*signals.Message, error) {
	// In a real implementation, this would deserialize the message
	// For now, we'll just return a placeholder message
	return &signals.Message{
		Sender:    []byte("placeholder"),
		Recipient: []byte("placeholder"),
		Type:      0,
		Payload:   data,
		Signature: []byte("placeholder"),
		Timestamp: time.Now().Unix(),
	}, nil
}

// checkAccessPolicy verifies if a message passes the access policy
func (fn *FederationNode) checkAccessPolicy(subject string, msg *signals.Message) bool {
	// Find the stream for this subject
	var streamName string
	for name, stream := range fn.streams {
		// Check if the stream handles this subject
		cfg, err := stream.Info()
		if err != nil {
			continue
		}
		
		for _, s := range cfg.Config.Subjects {
			if nats.IsSubjectMatch(s, subject) {
				streamName = name
				break
			}
		}
		
		if streamName != "" {
			break
		}
	}
	
	if streamName == "" {
		return false // No matching stream
	}
	
	// Get the access policy for this stream
	fn.policyMutex.RLock()
	policy, ok := fn.accessPolicies[streamName]
	fn.policyMutex.RUnlock()
	
	if !ok {
		return false // No policy defined
	}
	
	// In a real implementation, we would check the sender's identity
	// against the allowed identities in the policy
	// For now, we'll just return true for demonstration purposes
	return true
}

// PublishMessage publishes a message to a subject
func (fn *FederationNode) PublishMessage(subject string, msg *signals.Message) error {
	// Check if we have access to publish to this subject
	if !fn.checkAccessPolicy(subject, msg) {
		return errors.New("access denied for publishing to this subject")
	}
	
	// Serialize the message
	// In a real implementation, this would properly serialize the message
	data := msg.Payload
	
	// Publish the message
	_, err := fn.JetStream.Publish(fn.ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}
	
	return nil
}

// GetMessageChannel returns the channel for receiving messages
func (fn *FederationNode) GetMessageChannel() <-chan *signals.Message {
	return fn.messageCh
}

// Close shuts down the federation node
func (fn *FederationNode) Close() error {
	fn.cancel()
	
	// Close NATS connection
	fn.NatsConn.Close()
	
	// Close message channel
	close(fn.messageCh)
	
	return nil
}