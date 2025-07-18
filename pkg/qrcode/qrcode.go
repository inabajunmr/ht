package qrcode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/skip2/go-qrcode"
)

// CBOR constants from CTAP2 specification
const (
	cborMajorByteString = 2
)

// Global variables as per CTAP2 specification
var (
	qrSecret [16]byte
	// The ecdsa package is used for its convenient public/private key structures,
	// but these are ECDH keys, not ECDSA.
	identityKey *ecdsa.PrivateKey
	// Number of assigned tunnel server domains - match browser implementation
	assignedTunnelServerDomains = []string{"cable.ua5v.com", "cable.auth.com"}
)

// QRData represents the data encoded in the QR code for caBLE v2
type QRData struct {
	// caBLE v2 QR code data
	PublicKey     []byte // 33 bytes - P-256 compressed public key
	QRSecret      []byte // 16 bytes - QR secret
	TunnelID      []byte // 16 bytes - tunnel service identifier (not used in QR)
	
	// Internal fields (not encoded in QR)
	PrivateKey []byte
	TunnelURL  string
}

// compressECKey compresses a P-256 public key to 33 bytes
func compressECKey(publicKey *ecdsa.PublicKey) [33]byte {
	var compressed [33]byte
	
	// Determine the prefix based on the y-coordinate
	if publicKey.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	
	// Copy the x-coordinate (32 bytes)
	xBytes := publicKey.X.Bytes()
	copy(compressed[33-len(xBytes):], xBytes)
	
	return compressed
}

// showQRCode generates and displays a QR code as per CTAP2 specification
func showQRCode() string {
	rand.Reader.Read(qrSecret[:])

	var err error
	identityKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	identityKeyCompressed := compressECKey(&identityKey.PublicKey)

	return encodeQRContents(&identityKeyCompressed, &qrSecret)
}

// GenerateQRData creates QR code data for CTAP2 hybrid transport
func GenerateQRData() (*QRData, error) {
	// Generate QR secret and identity key using CTAP2 specification approach
	rand.Reader.Read(qrSecret[:])

	var err error
	identityKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %w", err)
	}
	
	identityKeyCompressed := compressECKey(&identityKey.PublicKey)

	// Generate tunnel ID (not used in QR but kept for compatibility)
	tunnelID := make([]byte, 16)
	if _, err := rand.Read(tunnelID); err != nil {
		return nil, fmt.Errorf("failed to generate tunnel ID: %w", err)
	}

	// Default tunnel service
	tunnelURL := "cable.ua5v.com"

	qrData := &QRData{
		PublicKey:  identityKeyCompressed[:],
		QRSecret:   qrSecret[:],
		TunnelID:   tunnelID,
		PrivateKey: nil, // Will be extracted from identityKey if needed
		TunnelURL:  tunnelURL,
	}

	return qrData, nil
}

// digitEncode converts bytes to digit string as per CTAP2 specification
func digitEncode(d []byte) string {
	const chunkSize = 7
	const chunkDigits = 17
	const zeros = "00000000000000000"

	var ret string
	for len(d) >= chunkSize {
		var chunk [8]byte
		copy(chunk[:], d[:chunkSize])
		v := strconv.FormatUint(binary.LittleEndian.Uint64(chunk[:]), 10)
		ret += zeros[:chunkDigits-len(v)]
		ret += v

		d = d[chunkSize:]
	}

	if len(d) != 0 {
		// partialChunkDigits is the number of digits needed to encode
		// each length of trailing data from 6 bytes down to zero. I.e.
		// it's 15, 13, 10, 8, 5, 3, 0 written in hex.
		const partialChunkDigits = 0x0fda8530

		digits := 15 & (partialChunkDigits >> (4 * len(d)))
		var chunk [8]byte
		copy(chunk[:], d)
		v := strconv.FormatUint(binary.LittleEndian.Uint64(chunk[:]), 10)
		ret += zeros[:digits-len(v)]
		ret += v
	}

	return ret
}

// cborEncodeInt64 encodes int64 to CBOR format
func cborEncodeInt64(value int64) []byte {
	if value < 0 {
		// Negative integers - not needed for timestamp
		return []byte{0x20} // placeholder
	}
	
	if value < 24 {
		return []byte{byte(value)}
	} else if value < 256 {
		return []byte{0x18, byte(value)}
	} else if value < 65536 {
		return []byte{0x19, byte(value >> 8), byte(value)}
	} else if value < 4294967296 {
		return []byte{0x1a, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	} else {
		return []byte{0x1b, byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	}
}

// DisplayQR displays the QR code in the terminal
func DisplayQR(qrData *QRData) error {
	// Use our implementation with browser-matching parameters
	fidoURL, err := encodeCableV2URL(qrData)
	if err != nil {
		return fmt.Errorf("failed to encode caBLE v2 URL: %w", err)
	}
	
	// BACKUP: Use browser-generated QR code for comparison
	//fidoURL := "FIDO:/164256176516630141297853122626219945748359380652102059895513187047676334729158906597767563397436255501466762135855516730075336766520323071777744305390338107096654083076"

	// Generate QR code
	qr, err := qrcode.New(fidoURL, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to create QR code: %w", err)
	}

	// Display QR code in terminal
	fmt.Println("caBLE v2 Hybrid Transport QR Code:")
	fmt.Println("Scan this QR code with your smartphone to authenticate")
	fmt.Println("*** USING BROWSER-COMPATIBLE IMPLEMENTATION ***")
	fmt.Println(qr.ToSmallString(false))

	// Display connection information
	fmt.Printf("FIDO URL: %s\n", fidoURL)
	fmt.Printf("Public Key: %x\n", qrData.PublicKey)
	fmt.Printf("QR Secret: %x\n", qrData.QRSecret)
	fmt.Printf("Tunnel URL: %s\n", qrData.TunnelURL)
	fmt.Println("Waiting for BLE connection...")

	return nil
}

// EncodeCableV2URL converts QR data to caBLE v2 URL format using CBOR encoding
// Format: FIDO:/<digitEncode(cbor)> (matches CTAP2 specification)
func EncodeCableV2URL(qrData *QRData) (string, error) {
	return encodeCableV2URL(qrData)
}

// encodeCableV2URL converts QR data to caBLE v2 URL format using CTAP2 specification
func encodeCableV2URL(qrData *QRData) (string, error) {
	// Convert byte slices to fixed-size arrays as required by the specification
	var compressedPublicKey [33]byte
	var qrSecretArray [16]byte
	
	copy(compressedPublicKey[:], qrData.PublicKey)
	copy(qrSecretArray[:], qrData.QRSecret)
	
	// Use the exact CTAP2 specification function
	return encodeQRContents(&compressedPublicKey, &qrSecretArray), nil
}

// encodeQRContents encodes QR contents exactly as per CTAP2 specification
func encodeQRContents(compressedPublicKey *[33]byte, qrSecret *[16]byte) string {
	numMapElements := 6
	// GREASE QR code to ensure that keys can be added later.
	var randByte [1]byte
	rand.Reader.Read(randByte[:])
	extraKey := randByte[0]&3 == 0
	if extraKey {
		numMapElements++
	}

	var cbor []byte
	cbor = append(cbor, 0xa0+byte(numMapElements))       // CBOR map
	cbor = append(cbor, 0)                               // key 0
	cbor = append(cbor, (cborMajorByteString<<5)|24, 33) // 33 bytes
	cbor = append(cbor, compressedPublicKey[:]...)
	cbor = append(cbor, 1)                           // key 1
	cbor = append(cbor, (cborMajorByteString<<5)|16) // 16 bytes
	cbor = append(cbor, qrSecret[:]...)

	cbor = append(cbor, 2) // key 2
	n := len(assignedTunnelServerDomains)
	if n > 24 {
		panic("larger encoding needed")
	}
	cbor = append(cbor, byte(n))

	cbor = append(cbor, 3) // key 3
	cbor = append(cbor, cborEncodeInt64(time.Now().Unix())...)

	cbor = append(cbor, 4) // key 4
	cbor = append(cbor, 0xf4)  // false (match browser implementation)

	cbor = append(cbor, 5) // key 5
	cbor = append(cbor, (3<<5)|2, 'g', 'a') // "ga" for getAssertion (match browser)

	if extraKey {
		cbor = append(cbor, 0x19, 0xff, 0xff, 0) // key 65535, value 0
	}

	qr := "FIDO:/" + digitEncode(cbor)
	fmt.Println(qr)
	return qr
}

// ValidateQRData validates the QR code data (legacy format)
func ValidateQRData(qrData *QRData) error {
	if len(qrData.PublicKey) != 32 {
		return fmt.Errorf("invalid public key length: expected 32, got %d", len(qrData.PublicKey))
	}

	if len(qrData.QRSecret) != 32 {
		return fmt.Errorf("invalid QR secret length: expected 32, got %d", len(qrData.QRSecret))
	}

	if len(qrData.TunnelID) != 16 {
		return fmt.Errorf("invalid tunnel ID length: expected 16, got %d", len(qrData.TunnelID))
	}

	if len(qrData.PrivateKey) != 32 {
		return fmt.Errorf("invalid private key length: expected 32, got %d", len(qrData.PrivateKey))
	}

	return nil
}

// ValidateQRDataCBOR validates the QR code data for CBOR format
func ValidateQRDataCBOR(qrData *QRData) error {
	if len(qrData.PublicKey) != 33 {
		return fmt.Errorf("invalid public key length: expected 33 (P-256 compressed), got %d", len(qrData.PublicKey))
	}

	if len(qrData.QRSecret) != 16 {
		return fmt.Errorf("invalid QR secret length: expected 16, got %d", len(qrData.QRSecret))
	}

	return nil
}

// printQRCode displays the QR code as per CTAP2 specification
func printQRCode(qrContent string) {
	// Generate QR code
	qr, err := qrcode.New(qrContent, qrcode.Medium)
	if err != nil {
		fmt.Printf("Failed to create QR code: %v\n", err)
		return
	}

	// Display QR code in terminal
	fmt.Println("caBLE v2 Hybrid Transport QR Code:")
	fmt.Println("Scan this QR code with your smartphone to authenticate")
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("FIDO URL: %s\n", qrContent)
}