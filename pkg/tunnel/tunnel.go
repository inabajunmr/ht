package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
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

	// Derive tunnel ID from QR secret according to caBLE specification
	// This is the 128-bit identifier that the tunnel service recognizes
	tunnelID, err := deriveTunnelID(qrSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive tunnel ID: %w", err)
	}

	return &Client{
		tunnelURL:  tunnelURL,
		privateKey: privateKey,
		publicKey:  publicKey,
		qrSecret:   qrSecret,
		tunnelID:   tunnelID,
		routingID:  nil, // Will be set from BLE advertisement
	}, nil
}

// deriveTunnelID derives the 128-bit tunnel ID from QR secret using HKDF
// according to caBLE specification with keyPurposeTunnelID = 2
func deriveTunnelID(qrSecret []byte) ([]byte, error) {
	// Use proper caBLE v2 key derivation with purpose = 2 (keyPurposeTunnelID)
	// This matches the specification: derive(tunnelID[:], qrSecret[:], nil, keyPurposeTunnelID)
	var purpose32 [4]byte
	purpose32[0] = byte(2) // keyPurposeTunnelID = 2
	// purpose32[1], purpose32[2], purpose32[3] remain zero
	
	hkdfReader := hkdf.New(sha256.New, qrSecret, nil, purpose32[:])
	
	tunnelID := make([]byte, 16) // 128 bits
	_, err := io.ReadFull(hkdfReader, tunnelID)
	if err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	
	log.Printf("Derived tunnel ID from QR secret (purpose=2): %x", tunnelID)
	return tunnelID, nil
}

// WaitForConnection waits for a connection from the authenticator
func (c *Client) WaitForConnection(ctx context.Context) (*Connection, error) {
	// Construct WebSocket URL following Chromium's caBLE v2 format
	// Based on Chromium source analysis and cable.google.com expected format:
	// wss://domain.googlevideo.com/connect/[base64-encoded-routing-id]/[base64-encoded-tunnel-id]
	// OR: wss://domain/connect/[routing-id-hex]/[tunnel-id-hex]
	
	// In caBLE v2, routing ID is 3 bytes and tunnel ID is 10 bytes (nonce)
	// Let's try the correct Google caBLE service URL format
	
	// Set up WebSocket connection according to Chromium caBLE specification
	// The example shows: Dial(connectURL, nil) - no custom headers
	
	// Ensure tunnelURL doesn't have protocol prefix
	domain := c.tunnelURL
	if strings.HasPrefix(domain, "wss://") {
		domain = strings.TrimPrefix(domain, "wss://")
	}
	if strings.HasPrefix(domain, "ws://") {
		domain = strings.TrimPrefix(domain, "ws://")
	}
	
	// Try multiple URL formats based on Chromium's caBLE implementation
	routingIDHex := hex.EncodeToString(c.routingID)
	tunnelIDHex := hex.EncodeToString(c.tunnelID)
	
	// Also try base64 encoding (URL-safe)
	routingIDB64 := base64.URLEncoding.EncodeToString(c.routingID)
	tunnelIDB64 := base64.URLEncoding.EncodeToString(c.tunnelID)
	
	log.Printf("Constructing WebSocket URL:")
	log.Printf("  Domain: %s", domain)
	log.Printf("  Routing ID (3 bytes): %x", c.routingID)
	log.Printf("  Tunnel ID (16 bytes): %x", c.tunnelID)
	log.Printf("  Routing ID (hex): %s", routingIDHex)
	log.Printf("  Tunnel ID (hex): %s", tunnelIDHex)
	log.Printf("  Routing ID (base64): %s", routingIDB64)
	log.Printf("  Tunnel ID (base64): %s", tunnelIDB64)
	
	// According to Chromium caBLE specification:
	// "In order to request a connection to a given tunnel ID, the path of the WebSockets URL is set to 
	// /cable/connect/ followed by the lower-case, hex-encoded routing ID, another foreslash, 
	// then the lower-case, hex-encoded tunnel ID."
	connectURL := fmt.Sprintf("wss://%s/cable/connect/%s/%s", domain, routingIDHex, tunnelIDHex)
	
	log.Printf("Using Chromium caBLE specification URL format:")
	log.Printf("  URL: %s", connectURL)
	
	// Focus on the official Chromium specification format only
	urlPatterns := []string{
		// Pattern 1: Official Chromium specification format
		connectURL,
	}
	
	log.Printf("Will try %d different URL patterns:", len(urlPatterns))
	for i, url := range urlPatterns {
		log.Printf("  Pattern %d: %s", i+1, url)
	}
	
	// Try each pattern
	for i, WSURL := range urlPatterns {
		log.Printf("Attempting connection with pattern %d: %s", i+1, WSURL)
		
		if conn, err := c.attemptConnection(ctx, WSURL); err == nil {
			log.Printf("Connection successful with pattern %d!", i+1)
			return conn, nil
		} else {
			log.Printf("Pattern %d failed: %v", i+1, err)
		}
	}
	
	return nil, fmt.Errorf("all connection patterns failed")
}

// attemptConnection tries to connect to a specific WebSocket URL
func (c *Client) attemptConnection(ctx context.Context, wsURL string) (*Connection, error) {
	log.Printf("WebSocket connection attempt:")
	log.Printf("  URL: %s", wsURL)
	
	// Match Chromium specification exactly - no custom headers, only subprotocol
	dialer := &websocket.Dialer{
		Subprotocols: []string{"fido.cable"},
	}
	
	log.Printf("  Subprotocols: %v", dialer.Subprotocols)
	log.Printf("Attempting WebSocket connection...")
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.Printf("WebSocket connection failed:")
		log.Printf("  Error: %v", err)
		if resp != nil {
			log.Printf("  HTTP Status: %s", resp.Status)
			log.Printf("  HTTP Status Code: %d", resp.StatusCode)
			log.Printf("  Response Headers:")
			for k, v := range resp.Header {
				log.Printf("    %s: %v", k, v)
			}
			
			// Read response body for detailed error information
			if resp.Body != nil {
				body, bodyErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if bodyErr == nil && len(body) > 0 {
					log.Printf("  Response Body (%d bytes):", len(body))
					// Print first 1000 characters to avoid excessive logging
					bodyStr := string(body)
					if len(bodyStr) > 1000 {
						bodyStr = bodyStr[:1000] + "... (truncated)"
					}
					log.Printf("    %s", bodyStr)
				} else if bodyErr != nil {
					log.Printf("  Failed to read response body: %v", bodyErr)
				}
			}
		}
		return nil, fmt.Errorf("failed to connect to tunnel service: %w", err)
	}
	
	log.Printf("WebSocket connection successful!")
	if resp != nil {
		log.Printf("  HTTP Status: %s", resp.Status)
		log.Printf("  Response Headers:")
		for k, v := range resp.Header {
			log.Printf("    %s: %v", k, v)
		}
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

	// Set read deadline for timeout
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

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

// SetTunnelInfo updates routing ID from BLE advertisement
// Note: tunnelID is derived from QR secret and should not be overwritten
func (c *Client) SetTunnelInfo(routingID, connectionNonce []byte) {
	c.routingID = routingID
	// connectionNonce is the nonce from BLE advertisement - we don't use it for tunnel ID
	// The tunnel ID was already correctly derived from QR secret in NewClient
	log.Printf("Updated routing ID from BLE advertisement: %x", routingID)
	log.Printf("Connection nonce from BLE: %x (not used for tunnel ID)", connectionNonce)
}