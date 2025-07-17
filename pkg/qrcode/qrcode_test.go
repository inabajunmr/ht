package qrcode

import (
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestGenerateQRData(t *testing.T) {
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData() failed: %v", err)
	}

	// Validate generated data
	if len(qrData.PublicKey) != 32 {
		t.Errorf("PublicKey length = %d, want 32", len(qrData.PublicKey))
	}

	if len(qrData.QRSecret) != 32 {
		t.Errorf("QRSecret length = %d, want 32", len(qrData.QRSecret))
	}

	if qrData.TunnelDomains == 0 {
		t.Error("TunnelDomains should be greater than 0")
	}

	if len(qrData.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(qrData.PrivateKey))
	}

	if qrData.TunnelURL == "" {
		t.Error("TunnelURL should not be empty")
	}

	if qrData.Timestamp == 0 {
		t.Error("Timestamp should not be zero")
	}

	// Test timestamp is recent (within 1 minute)
	now := time.Now().Unix()
	if now-qrData.Timestamp > 60 {
		t.Errorf("Timestamp too old: %d", now-qrData.Timestamp)
	}
}

func TestValidateQRData(t *testing.T) {
	// Test valid QR data
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData() failed: %v", err)
	}

	if err := ValidateQRData(qrData); err != nil {
		t.Errorf("ValidateQRData() failed: %v", err)
	}

	// Test invalid public key length
	qrData.PublicKey = make([]byte, 16)
	if err := ValidateQRData(qrData); err == nil {
		t.Error("ValidateQRData() should fail with invalid public key length")
	}

	// Reset and test invalid QR secret length
	qrData, _ = GenerateQRData()
	qrData.QRSecret = make([]byte, 16)
	if err := ValidateQRData(qrData); err == nil {
		t.Error("ValidateQRData() should fail with invalid QR secret length")
	}

	// Reset and test invalid tunnel domains
	qrData, _ = GenerateQRData()
	qrData.TunnelDomains = 0
	if err := ValidateQRData(qrData); err == nil {
		t.Error("ValidateQRData() should fail with invalid tunnel domains")
	}

	// Reset and test old timestamp
	qrData, _ = GenerateQRData()
	qrData.Timestamp = time.Now().Unix() - 700 // 11+ minutes old
	if err := ValidateQRData(qrData); err == nil {
		t.Error("ValidateQRData() should fail with old timestamp")
	}
}

func TestEncodeFidoURL(t *testing.T) {
	// Test FIDO URL encoding
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	fidoURL, err := encodeFidoURL(testData)
	if err != nil {
		t.Fatalf("encodeFidoURL failed: %v", err)
	}

	if !strings.HasPrefix(fidoURL, "FIDO:/") {
		t.Error("FIDO URL should start with FIDO:/")
	}

	// Should be 17 digits after FIDO:/
	decimalPart := strings.TrimPrefix(fidoURL, "FIDO:/")
	if len(decimalPart) != 17 {
		t.Errorf("Expected 17 digits, got %d", len(decimalPart))
	}

	// Should be all digits
	for _, r := range decimalPart {
		if r < '0' || r > '9' {
			t.Errorf("Non-digit character found: %c", r)
		}
	}
}

func TestQRDataCBOREncoding(t *testing.T) {
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("GenerateQRData() failed: %v", err)
	}

	// Test CBOR encoding
	cborData, err := cbor.Marshal(qrData)
	if err != nil {
		t.Fatalf("CBOR marshal failed: %v", err)
	}

	// Test CBOR decoding
	var decoded QRData
	if err := cbor.Unmarshal(cborData, &decoded); err != nil {
		t.Fatalf("CBOR unmarshal failed: %v", err)
	}

	// Compare key fields (private key and tunnel URL should not be in CBOR)
	if string(decoded.PublicKey) != string(qrData.PublicKey) {
		t.Error("PublicKey mismatch after CBOR round-trip")
	}

	if string(decoded.QRSecret) != string(qrData.QRSecret) {
		t.Error("QRSecret mismatch after CBOR round-trip")
	}

	if decoded.TunnelDomains != qrData.TunnelDomains {
		t.Error("TunnelDomains mismatch after CBOR round-trip")
	}

	if decoded.StateAssisted != qrData.StateAssisted {
		t.Error("StateAssisted mismatch after CBOR round-trip")
	}

	if decoded.Timestamp != qrData.Timestamp {
		t.Error("Timestamp mismatch after CBOR round-trip")
	}

	// Private key should not be in CBOR
	if len(decoded.PrivateKey) != 0 {
		t.Error("PrivateKey should not be encoded in CBOR")
	}

	// Tunnel URL should not be in CBOR
	if decoded.TunnelURL != "" {
		t.Error("TunnelURL should not be encoded in CBOR")
	}
}