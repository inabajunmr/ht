package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

// Client handles tunnel service communication
type Client struct {
	tunnelURL  string
	privateKey []byte
}

// Connection represents a tunnel connection
type Connection struct {
	conn net.Conn
}

// NewClient creates a new tunnel client
func NewClient(tunnelURL string, privateKey []byte) (*Client, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privateKey))
	}

	return &Client{
		tunnelURL:  tunnelURL,
		privateKey: privateKey,
	}, nil
}

// WaitForConnection waits for a connection from the authenticator
func (c *Client) WaitForConnection(ctx context.Context) (*Connection, error) {
	log.Printf("Waiting for tunnel connection at: %s", c.tunnelURL)
	log.Printf("Private key: %x", c.privateKey)

	// TODO: Implement actual tunnel service connection
	// For now, simulate waiting for connection
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for connection (stub implementation)")
	}
}

// Close closes the tunnel connection
func (c *Connection) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Read reads data from the tunnel connection
func (c *Connection) Read(p []byte) (int, error) {
	if c.conn != nil {
		return c.conn.Read(p)
	}
	return 0, fmt.Errorf("connection not established")
}

// Write writes data to the tunnel connection
func (c *Connection) Write(p []byte) (int, error) {
	if c.conn != nil {
		return c.conn.Write(p)
	}
	return 0, fmt.Errorf("connection not established")
}