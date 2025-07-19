package ble

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/hkdf"
)

// caBLE v2 cryptographic constants
const (
	CableV2EIDKeyLength    = 64  // EID key length (32 bytes AES + 32 bytes HMAC)
	CableV2AESKeyLength    = 32  // AES key length
	CableV2HMACKeyLength   = 32  // HMAC key length  
	CableV2AdvertLength    = 20  // BLE advertisement length
	CableV2PlaintextLength = 16  // Decrypted plaintext length
	CableV2HMACTagLength   = 4   // HMAC tag length (first 4 bytes of SHA256)
)

// caBLE v2 key purposes for HKDF
type keyPurpose uint32

const (
	keyPurposeEIDKey   keyPurpose = 1
	keyPurposeTunnelID keyPurpose = 2
	keyPurposePSK      keyPurpose = 3
)

// CableV2Decryptor handles caBLE v2 service data decryption
type CableV2Decryptor struct {
	qrSecret []byte
}

// NewCableV2Decryptor creates a new caBLE v2 decryptor
func NewCableV2Decryptor(qrSecret []byte) *CableV2Decryptor {
	return &CableV2Decryptor{
		qrSecret: qrSecret,
	}
}

// DecryptServiceData decrypts caBLE v2 service data using QR secret
func (d *CableV2Decryptor) DecryptServiceData(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) != CableV2AdvertLength {
		return nil, fmt.Errorf("invalid encrypted data length: expected %d bytes, got %d", CableV2AdvertLength, len(encryptedData))
	}

	log.Printf("Decrypting caBLE v2 service data: %x", encryptedData)

	// Derive the 64-byte EID key from QR secret using proper caBLE v2 HKDF
	var eidKey [CableV2EIDKeyLength]byte
	if err := d.derive(eidKey[:], d.qrSecret, nil, keyPurposeEIDKey); err != nil {
		return nil, fmt.Errorf("failed to derive EID key: %w", err)
	}

	log.Printf("Derived EID key (first 8 bytes): %x", eidKey[:8])

	// Trial decrypt using caBLE v2 specification: AES-ECB + HMAC
	plaintext, ok := d.trialDecrypt(&eidKey, encryptedData)
	if !ok {
		return nil, fmt.Errorf("caBLE v2 authentication/decryption failed")
	}

	log.Printf("Successfully decrypted caBLE v2 service data: %x", plaintext[:])
	return plaintext[:], nil
}

// derive implements caBLE v2 HKDF key derivation with purpose
func (d *CableV2Decryptor) derive(output, secret, salt []byte, purpose keyPurpose) error {
	if uint32(purpose) >= 0x100 {
		return fmt.Errorf("unsupported purpose: %d", purpose)
	}

	// Purpose is encoded as 32-bit little-endian
	var purpose32 [4]byte
	purpose32[0] = byte(purpose)
	// purpose32[1], purpose32[2], purpose32[3] remain zero

	h := hkdf.New(sha256.New, secret, salt, purpose32[:])
	n, err := h.Read(output)
	if err != nil || n != len(output) {
		return fmt.Errorf("HKDF error: read %d bytes, expected %d, err: %v", n, len(output), err)
	}

	return nil
}

// trialDecrypt implements caBLE v2 trial decryption: AES-ECB + HMAC verification
func (d *CableV2Decryptor) trialDecrypt(eidKey *[CableV2EIDKeyLength]byte, candidateAdvert []byte) ([CableV2PlaintextLength]byte, bool) {
	var zeros [CableV2PlaintextLength]byte
	
	if len(candidateAdvert) != CableV2AdvertLength {
		log.Printf("Invalid advert length: %d, expected %d", len(candidateAdvert), CableV2AdvertLength)
		return zeros, false
	}

	// Split EID key: first 32 bytes for AES, second 32 bytes for HMAC
	aesKey := eidKey[:CableV2AESKeyLength]
	hmacKey := eidKey[CableV2AESKeyLength:]

	log.Printf("AES key (first 8 bytes): %x", aesKey[:8])
	log.Printf("HMAC key (first 8 bytes): %x", hmacKey[:8])

	// Verify HMAC: last 4 bytes should be HMAC-SHA256 of first 16 bytes
	h := hmac.New(sha256.New, hmacKey)
	h.Write(candidateAdvert[:16])
	expectedTag := h.Sum(nil)

	log.Printf("First 16 bytes: %x", candidateAdvert[:16])
	log.Printf("Last 4 bytes (tag): %x", candidateAdvert[16:])
	log.Printf("Expected HMAC tag (first 4 bytes): %x", expectedTag[:4])

	if !hmac.Equal(expectedTag[:4], candidateAdvert[16:]) {
		log.Printf("HMAC verification failed")
		return zeros, false
	}

	log.Printf("HMAC verification successful")

	// Decrypt first 16 bytes using AES-ECB (single block)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Printf("Failed to create AES cipher: %v", err)
		return zeros, false
	}

	var plaintext [CableV2PlaintextLength]byte
	block.Decrypt(plaintext[:], candidateAdvert[:16])

	log.Printf("Decrypted plaintext: %x", plaintext[:])

	// Verify reserved bits are zero (first byte should be 0)
	if !d.reservedBitsAreZero(plaintext) {
		log.Printf("Reserved bits validation failed: first byte is %02x, expected 0", plaintext[0])
		return zeros, false
	}

	log.Printf("Reserved bits validation successful")
	return plaintext, true
}

// reservedBitsAreZero checks if the first byte (flags) is zero
func (d *CableV2Decryptor) reservedBitsAreZero(plaintext [CableV2PlaintextLength]byte) bool {
	return plaintext[0] == 0
}

// ParseDecryptedServiceData parses decrypted caBLE v2 service data according to specification
func ParseDecryptedServiceData(decryptedData []byte) (nonce []byte, routingID []byte, tunnelService []byte, additionalData []byte, err error) {
	if len(decryptedData) != CableV2PlaintextLength {
		return nil, nil, nil, nil, fmt.Errorf("invalid decrypted data length: expected %d bytes, got %d", CableV2PlaintextLength, len(decryptedData))
	}

	// Parse according to caBLE v2 specification:
	// [1 byte flags (must be 0)] + [10 bytes connection nonce] + [3 bytes routing ID] + [2 bytes tunnel service]
	
	// Skip flags byte (index 0)
	nonce = make([]byte, 10)
	copy(nonce, decryptedData[1:11])
	
	routingID = make([]byte, 3)
	copy(routingID, decryptedData[11:14])
	
	tunnelService = make([]byte, 2)
	copy(tunnelService, decryptedData[14:16])
	
	// No additional data in caBLE v2 spec
	additionalData = nil

	return nonce, routingID, tunnelService, additionalData, nil
}

// UnpackDecryptedAdvert unpacks a decrypted caBLE v2 advertisement according to specification
func UnpackDecryptedAdvert(plaintext [CableV2PlaintextLength]byte) (nonce [10]byte, routingID [3]byte, encodedTunnelServerDomain uint16) {
	copy(nonce[:], plaintext[1:11])
	copy(routingID[:], plaintext[11:14])
	encodedTunnelServerDomain = uint16(plaintext[14]) | (uint16(plaintext[15]) << 8)
	return
}