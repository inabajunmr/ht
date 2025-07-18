package qrcode

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateQRData(t *testing.T) {
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData() failed: %v", err)
	}

	// Validate generated data for CBOR format
	if len(qrData.PublicKey) != 33 {
		t.Errorf("PublicKey length = %d, want 33 (P-256 compressed)", len(qrData.PublicKey))
	}

	if len(qrData.QRSecret) != 16 {
		t.Errorf("QRSecret length = %d, want 16", len(qrData.QRSecret))
	}

	if len(qrData.TunnelID) != 16 {
		t.Errorf("TunnelID length = %d, want 16", len(qrData.TunnelID))
	}

	// Private key is stored in the global identityKey variable in CTAP2 spec
	if identityKey == nil {
		t.Error("identityKey should not be nil")
	}

	if qrData.TunnelURL == "" {
		t.Error("TunnelURL should not be empty")
	}

}

func TestValidateQRData(t *testing.T) {
	// Test valid QR data with CBOR format
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData() failed: %v", err)
	}

	if err := ValidateQRDataCBOR(qrData); err != nil {
		t.Errorf("ValidateQRDataCBOR() failed: %v", err)
	}

	// Test invalid public key length
	qrData.PublicKey = make([]byte, 16)
	if err := ValidateQRDataCBOR(qrData); err == nil {
		t.Error("ValidateQRDataCBOR() should fail with invalid public key length")
	}

	// Reset and test invalid QR secret length
	qrData, _ = GenerateQRData()
	qrData.QRSecret = make([]byte, 32)
	if err := ValidateQRDataCBOR(qrData); err == nil {
		t.Error("ValidateQRDataCBOR() should fail with invalid QR secret length")
	}

	// Test legacy validation should fail with new format
	qrData, _ = GenerateQRData()
	if err := ValidateQRData(qrData); err == nil {
		t.Error("ValidateQRData() should fail with CBOR format data")
	}
}

func TestEncodeCableV2URL(t *testing.T) {
	// Test caBLE v2 URL encoding with CBOR format
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData failed: %v", err)
	}

	cableURL, err := encodeCableV2URL(qrData)
	if err != nil {
		t.Fatalf("encodeCableV2URL failed: %v", err)
	}

	if !strings.HasPrefix(cableURL, "FIDO:/") {
		t.Error("caBLE URL should start with FIDO:/")
	}

	// Should have numeric data after prefix
	dataPart := strings.TrimPrefix(cableURL, "FIDO:/")
	if len(dataPart) == 0 {
		t.Error("caBLE URL should have encoded data")
	}

	// Should be valid numeric string
	for _, r := range dataPart {
		if !(r >= '0' && r <= '9') {
			t.Errorf("Invalid numeric character found: %c", r)
		}
	}

	t.Logf("Generated caBLE URL: %s", cableURL)
}

func TestQRDataValidation(t *testing.T) {
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData() failed: %v", err)
	}

	// Test validation passes for valid data using CBOR format
	if err := ValidateQRDataCBOR(qrData); err != nil {
		t.Errorf("ValidateQRDataCBOR() failed for valid data: %v", err)
	}

	// Test that all required fields have correct lengths for CBOR format
	if len(qrData.PublicKey) != 33 {
		t.Error("PublicKey should be 33 bytes (P-256 compressed)")
	}

	if len(qrData.QRSecret) != 16 {
		t.Error("QRSecret should be 16 bytes")
	}

	if len(qrData.TunnelID) != 16 {
		t.Error("TunnelID should be 16 bytes")
	}

	// Private key is handled by global identityKey variable
	if identityKey == nil {
		t.Error("identityKey should not be nil")
	}

	// Test URL generation
	url, err := encodeCableV2URL(qrData)
	if err != nil {
		t.Errorf("encodeCableV2URL failed: %v", err)
	}

	if !strings.HasPrefix(url, "FIDO:/") {
		t.Error("URL should start with FIDO:/")
	}
}

// Test Chromium-compatible CBOR encoding for caBLE v2
func TestCBOREncodingChromiumFormat(t *testing.T) {
	// Test case based on Chromium's caBLE v2 implementation
	// QR code should contain CBOR-encoded map with specific keys
	
	// Create test QR data with P-256 compressed public key (33 bytes)
	publicKey, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021") // 33 bytes P-256 compressed
	qrSecret, _ := hex.DecodeString("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") // 16 bytes
	
	qrData := &QRData{
		PublicKey:  publicKey,
		QRSecret:   qrSecret,
		TunnelID:   []byte{}, // Not used in CBOR format
		PrivateKey: make([]byte, 32),
		TunnelURL:  "cable.ua5v.com",
	}
	
	// Test CBOR encoding using specification function
	url, err := encodeCableV2URL(qrData)
	if err != nil {
		t.Fatalf("Failed to encode CBOR map: %v", err)
	}
	
	// URL should not be empty
	if len(url) == 0 {
		t.Error("URL is empty")
	}
	
	t.Logf("Generated URL: %s", url)
	t.Logf("URL length: %d characters", len(url))
	
	// URL should start with "FIDO:/"
	if !strings.HasPrefix(url, "FIDO:/") {
		t.Errorf("Expected URL to start with 'FIDO:/', got: %s", url[:7])
	}
	
	// Should contain encoded data
	t.Logf("Generated CTAP2-compliant URL: %s", url)
	
	// Verify the URL contains expected structure
	if len(url) < 20 {
		t.Errorf("URL seems too short: %s", url)
	}
}

func TestValidateQRDataCBOR(t *testing.T) {
	// Test validation for CBOR format
	validPublicKey := make([]byte, 33) // P-256 compressed is 33 bytes
	validQRSecret := make([]byte, 16)  // QR secret is 16 bytes
	
	qrData := &QRData{
		PublicKey:  validPublicKey,
		QRSecret:   validQRSecret,
		TunnelID:   []byte{}, // Not used in CBOR format
		PrivateKey: make([]byte, 32),
		TunnelURL:  "cable.ua5v.com",
	}
	
	err := ValidateQRDataCBOR(qrData)
	if err != nil {
		t.Errorf("Validation failed for valid data: %v", err)
	}
	
	// Test invalid public key length
	qrData.PublicKey = make([]byte, 32) // Wrong length
	err = ValidateQRDataCBOR(qrData)
	if err == nil {
		t.Error("Expected validation error for invalid public key length")
	}
	
	// Test invalid QR secret length
	qrData.PublicKey = validPublicKey
	qrData.QRSecret = make([]byte, 32) // Wrong length
	err = ValidateQRDataCBOR(qrData)
	if err == nil {
		t.Error("Expected validation error for invalid QR secret length")
	}
}