package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Client handles tunnel service communication
type Client struct {
	tunnelURL    string
	privateKey   []byte
	publicKey    []byte
	qrSecret     []byte
	tunnelID     []byte
	routingID    []byte
	conn         *websocket.Conn
	handshakeKey []byte
}

// Connection represents a tunnel connection
type Connection struct {
	conn       *websocket.Conn
	encryptKey []byte
	decryptKey []byte
	sequenceNo uint64
}

// NewClient creates a new tunnel client
func NewClient(tunnelURL string, privateKey []byte, publicKey []byte, qrSecret []byte) (*Client, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privateKey))
	}
	if len(publicKey) != 33 {
		return nil, fmt.Errorf("public key must be 33 bytes, got %d", len(publicKey))
	}
	if len(qrSecret) != 16 {
		return nil, fmt.Errorf("QR secret must be 16 bytes, got %d", len(qrSecret))
	}

	// Generate tunnel ID and routing ID
	tunnelID := make([]byte, 16)
	routingID := make([]byte, 16)
	rand.Read(tunnelID)
	rand.Read(routingID)

	return &Client{
		tunnelURL:  tunnelURL,
		privateKey: privateKey,
		publicKey:  publicKey,
		qrSecret:   qrSecret,
		tunnelID:   tunnelID,
		routingID:  routingID,
	}, nil
}

// WaitForConnection waits for a connection from the authenticator
func (c *Client) WaitForConnection(ctx context.Context) (*Connection, error) {
	// Construct WebSocket URL following Chromium's caBLE v2 format
	// wss://[domain]/cable/connect/[routing-id]/[tunnel-id]
	tunnelIDHex := hex.EncodeToString(c.tunnelID)
	routingIDHex := hex.EncodeToString(c.routingID)
	
	WSURL := fmt.Sprintf("wss://%s/cable/connect/%s/%s", c.tunnelURL, routingIDHex, tunnelIDHex)
	log.Printf("Connecting to tunnel service: %s", WSURL)

	// Set up WebSocket connection with proper headers
	header := http.Header{}
	header.Set("Sec-WebSocket-Protocol", "fido.cable")
	
	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(WSURL, header)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tunnel service: %w", err)
	}

	c.conn = conn
	log.Printf("WebSocket connection established")

	// Perform caBLE v2 handshake (desktop-speaks-first)
	handshakeConn, err := c.performHandshake(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	log.Printf("Handshake completed successfully")
	return handshakeConn, nil
}

// performHandshake performs the caBLE v2 handshake using Noise protocol
func (c *Client) performHandshake(ctx context.Context) (*Connection, error) {
	// Derive handshake key using HKDF
	handshakeKey, err := c.deriveHandshakeKey()
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	c.handshakeKey = handshakeKey

	// Desktop-speaks-first handshake
	// Send initial handshake message
	initialMessage, err := c.createInitialHandshakeMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to create initial message: %w", err)
	}

	err = c.conn.WriteMessage(websocket.BinaryMessage, initialMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to send initial handshake: %w", err)
	}

	log.Printf("Sent initial handshake message (%d bytes)", len(initialMessage))

	// Wait for response from phone
	_, responseMessage, err := c.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	log.Printf("Received handshake response (%d bytes)", len(responseMessage))

	// Process handshake response and derive session keys
	encryptKey, decryptKey, err := c.processHandshakeResponse(responseMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to process handshake response: %w", err)
	}

	return &Connection{
		conn:       c.conn,
		encryptKey: encryptKey,
		decryptKey: decryptKey,
		sequenceNo: 0,
	}, nil
}

// deriveHandshakeKey derives the handshake key using HKDF
func (c *Client) deriveHandshakeKey() ([]byte, error) {
	// Use QR secret as input key material
	hkdfReader := hkdf.New(sha256.New, c.qrSecret, nil, []byte("caBLE v2 handshake"))
	
	key := make([]byte, 32)
	_, err := hkdfReader.Read(key)
	if err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	
	return key, nil
}

// createInitialHandshakeMessage creates the initial handshake message
func (c *Client) createInitialHandshakeMessage() ([]byte, error) {
	// Create handshake message with public key and nonce
	nonce := make([]byte, 12)
	rand.Read(nonce)
	
	// Message format: [public_key(33)] + [nonce(12)] + [encrypted_payload]
	message := make([]byte, 0, 33+12+32)
	message = append(message, c.publicKey...)
	message = append(message, nonce...)
	
	// Create encrypted payload using handshake key
	cipher, err := chacha20poly1305.New(c.handshakeKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}
	
	payload := []byte("desktop-handshake-v2")
	encryptedPayload := cipher.Seal(nil, nonce, payload, c.publicKey)
	message = append(message, encryptedPayload...)
	
	return message, nil
}

// processHandshakeResponse processes the handshake response and derives session keys
func (c *Client) processHandshakeResponse(response []byte) ([]byte, []byte, error) {
	if len(response) < 45 { // 33 (pubkey) + 12 (nonce) + minimum encrypted data
		return nil, nil, fmt.Errorf("handshake response too short: %d bytes", len(response))
	}
	
	// Extract components
	phonePublicKey := response[:33]
	nonce := response[33:45]
	encryptedPayload := response[45:]
	
	// Decrypt payload
	cipher, err := chacha20poly1305.New(c.handshakeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher creation failed: %w", err)
	}
	
	payload, err := cipher.Open(nil, nonce, encryptedPayload, phonePublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	log.Printf("Decrypted handshake payload: %s", string(payload))
	
	// Derive session keys using both public keys
	encryptKey, decryptKey, err := c.deriveSessionKeys(phonePublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("session key derivation failed: %w", err)
	}
	
	return encryptKey, decryptKey, nil
}

// deriveSessionKeys derives session keys for encryption/decryption
func (c *Client) deriveSessionKeys(phonePublicKey []byte) ([]byte, []byte, error) {
	// Combine keys for session key derivation
	sharedInfo := append(c.publicKey, phonePublicKey...)
	
	hkdfReader := hkdf.New(sha256.New, c.handshakeKey, nil, append([]byte("caBLE v2 session"), sharedInfo...))
	
	encryptKey := make([]byte, 32)
	decryptKey := make([]byte, 32)
	
	_, err := hkdfReader.Read(encryptKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt key derivation failed: %w", err)
	}
	
	_, err = hkdfReader.Read(decryptKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt key derivation failed: %w", err)
	}
	
	return encryptKey, decryptKey, nil
}

// Close closes the tunnel connection
func (c *Connection) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ReadMessage reads and decrypts a message from the tunnel connection
func (c *Connection) ReadMessage() ([]byte, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("connection not established")
	}

	_, encryptedMessage, err := c.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	return c.decryptMessage(encryptedMessage)
}

// decryptMessage decrypts an incoming message
func (c *Connection) decryptMessage(encryptedMessage []byte) ([]byte, error) {
	if len(encryptedMessage) < 28 { // 12 (nonce) + 16 (tag) + minimum data
		return nil, fmt.Errorf("encrypted message too short: %d bytes", len(encryptedMessage))
	}

	cipher, err := chacha20poly1305.New(c.decryptKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	// Extract nonce and ciphertext
	nonce := encryptedMessage[:12]
	ciphertext := encryptedMessage[12:]

	// Decrypt message
	plaintext, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// WriteMessage encrypts and writes a message to the tunnel connection
func (c *Connection) WriteMessage(message []byte) error {
	if c.conn == nil {
		return fmt.Errorf("connection not established")
	}

	encryptedMessage, err := c.encryptMessage(message)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	return c.conn.WriteMessage(websocket.BinaryMessage, encryptedMessage)
}

// encryptMessage encrypts an outgoing message
func (c *Connection) encryptMessage(message []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(c.encryptKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	// Generate nonce using sequence number
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[:8], c.sequenceNo)
	c.sequenceNo++

	// Encrypt message
	ciphertext := cipher.Seal(nil, nonce, message, nil)

	// Prepend nonce to ciphertext
	encryptedMessage := append(nonce, ciphertext...)

	return encryptedMessage, nil
}

// GetTunnelInfo returns tunnel connection information
func (c *Client) GetTunnelInfo() (string, string, string) {
	tunnelIDHex := hex.EncodeToString(c.tunnelID)
	routingIDHex := hex.EncodeToString(c.routingID)
	return c.tunnelURL, routingIDHex, tunnelIDHex
}

// SetTunnelInfo updates tunnel connection information from BLE advertisement
func (c *Client) SetTunnelInfo(routingID, tunnelID []byte) {
	c.routingID = routingID
	c.tunnelID = tunnelID
}