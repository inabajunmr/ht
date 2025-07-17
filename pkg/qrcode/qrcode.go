package qrcode

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/curve25519"
)

// QRData represents the data encoded in the QR code for CTAP2 hybrid transport
type QRData struct {
	PublicKey     []byte `cbor:"0"`
	QRSecret      []byte `cbor:"1"`
	TunnelDomains uint8  `cbor:"2"`
	Timestamp     int64  `cbor:"3"`
	StateAssisted bool   `cbor:"4"`
	OperationHint uint8  `cbor:"5"`
	
	// Internal fields (not encoded in QR)
	PrivateKey []byte `cbor:"-"`
	TunnelURL  string `cbor:"-"`
}

// GenerateQRData creates QR code data for CTAP2 hybrid transport
func GenerateQRData() (*QRData, error) {
	// Generate key pair for the connection
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	// Generate QR secret for BLE encryption
	qrSecret := make([]byte, 32)
	if _, err := rand.Read(qrSecret); err != nil {
		return nil, fmt.Errorf("failed to generate QR secret: %w", err)
	}

	// Default tunnel service (Google's service)
	tunnelURL := "wss://cableconnect.googleapis.com/v1/connect"

	qrData := &QRData{
		PublicKey:     publicKey,
		QRSecret:      qrSecret,
		TunnelDomains: 1, // Number of known tunnel service domains
		Timestamp:     time.Now().Unix(),
		StateAssisted: true, // Supports state-assisted transactions
		OperationHint: 1,    // Authentication operation
		PrivateKey:    privateKey,
		TunnelURL:     tunnelURL,
	}

	return qrData, nil
}

// DisplayQR displays the QR code in the terminal
func DisplayQR(qrData *QRData) error {
	// Encode QR data as CBOR
	cborData, err := cbor.Marshal(qrData)
	if err != nil {
		return fmt.Errorf("failed to encode QR data: %w", err)
	}

	// Convert CBOR to FIDO:/ URL format
	fidoURL, err := encodeFidoURL(cborData)
	if err != nil {
		return fmt.Errorf("failed to encode FIDO URL: %w", err)
	}

	// Generate QR code
	qr, err := qrcode.New(fidoURL, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to create QR code: %w", err)
	}

	// Display QR code in terminal
	fmt.Println("CTAP2 Hybrid Transport QR Code:")
	fmt.Println("Scan this QR code with your smartphone to authenticate")
	fmt.Println(qr.ToSmallString(false))

	// Display connection information
	fmt.Printf("FIDO URL: %s\n", fidoURL)
	fmt.Printf("CBOR Data Length: %d bytes\n", len(cborData))
	fmt.Printf("Timestamp: %d\n", qrData.Timestamp)
	fmt.Println("Waiting for BLE connection...")

	return nil
}

// encodeFidoURL converts CBOR data to FIDO:/ URL format
// CTAP2.2 uses decimal encoding: 7 bytes -> 17 decimal digits
func encodeFidoURL(cborData []byte) (string, error) {
	var result string
	
	// Process data in chunks of 7 bytes
	for i := 0; i < len(cborData); i += 7 {
		// Get up to 7 bytes
		chunk := make([]byte, 7)
		for j := 0; j < 7 && i+j < len(cborData); j++ {
			chunk[j] = cborData[i+j]
		}
		
		// Convert 7 bytes to big integer (little-endian)
		var value big.Int
		for j := 6; j >= 0; j-- {
			value.Lsh(&value, 8)
			value.Or(&value, big.NewInt(int64(chunk[j])))
		}
		
		// Convert to 17-digit decimal string
		decimalStr := fmt.Sprintf("%017s", value.String())
		result += decimalStr
	}
	
	return "FIDO:/" + result, nil
}

// ValidateQRData validates the QR code data
func ValidateQRData(qrData *QRData) error {
	if len(qrData.PublicKey) != 32 {
		return fmt.Errorf("invalid public key length: expected 32, got %d", len(qrData.PublicKey))
	}

	if len(qrData.QRSecret) != 32 {
		return fmt.Errorf("invalid QR secret length: expected 32, got %d", len(qrData.QRSecret))
	}

	if qrData.TunnelDomains == 0 {
		return fmt.Errorf("tunnel domains must be greater than 0")
	}

	// Check timestamp is not too old (within 10 minutes)
	now := time.Now().Unix()
	if now-qrData.Timestamp > 600 {
		return fmt.Errorf("QR code is too old")
	}

	return nil
}