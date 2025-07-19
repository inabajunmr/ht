package ble

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestCableV2Decryption tests caBLE v2 BLE advertisement decryption using known working test vectors
func TestCableV2Decryption(t *testing.T) {
	// Since our implementation works with real devices, but we need consistent test vectors,
	// let's create synthetic but realistic test cases that we can validate
	testCases := []struct {
		name               string
		qrSecret           string
		encryptedServiceData string
		expectedPlaintext   string
		expectedNonce      string
		expectedRoutingID  string
		expectedTunnelService string
		shouldSucceed      bool
	}{
		{
			name:               "Synthetic test case 1",
			qrSecret:           "3e3bb1c00f37e7380280f2b1f2fc3846",  // 16 bytes QR secret
			encryptedServiceData: "5fe6149e9950f5957a92a0ebc8c1766d80969202",  // 20 bytes encrypted service data
			expectedPlaintext:   "00b89c04c7dc93c57a1ceb801be00000",
			expectedNonce:      "b89c04c7dc93c57a1ceb",
			expectedRoutingID:  "801be0",
			expectedTunnelService: "0000",
			shouldSucceed:      true,
		},
		{
			name:               "Synthetic test case 2", 
			qrSecret:           "f260d8c9c60ce46fe38aa666fba688ed",  // 16 bytes QR secret
			encryptedServiceData: "1609f251713aa68259ddc1fddc21d86ca16f9f37",  // 20 bytes encrypted service data
			expectedPlaintext:   "00a2489a79df0ea8e9989d8924086f72",
			expectedNonce:      "a2489a79df0ea8e9989d",
			expectedRoutingID:  "892408",
			expectedTunnelService: "6f72",
			shouldSucceed:      true,
		},
		{
			name:               "Wrong QR secret should fail",
			qrSecret:           "00000000000000000000000000000000",
			encryptedServiceData: "5fe6149e9950f5957a92a0ebc8c1766d80969202",  // Use synthetic test case 1 data
			expectedPlaintext:   "",
			shouldSucceed:      false,
		},
		{
			name:               "Invalid data length should fail",
			qrSecret:           "3e3bb1c00f37e7380280f2b1f2fc3846",
			encryptedServiceData: "5fe6149e9950f5957a92a0ebc8c1766d",  // Only 16 bytes
			expectedPlaintext:   "",
			shouldSucceed:      false,
		},
		{
			name:               "Corrupted service data should fail",
			qrSecret:           "3e3bb1c00f37e7380280f2b1f2fc3846",
			encryptedServiceData: "5fe6149e9950f5957a92a0ebc8c1766dffffffff",  // Corrupted last 4 bytes
			expectedPlaintext:   "",
			shouldSucceed:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Decode hex strings
			qrSecret, err := hex.DecodeString(tc.qrSecret)
			if err != nil {
				t.Fatalf("Failed to decode QR secret: %v", err)
			}

			encryptedData, err := hex.DecodeString(tc.encryptedServiceData)
			if err != nil {
				t.Fatalf("Failed to decode encrypted service data: %v", err)
			}

			// Create decryptor
			decryptor := NewCableV2Decryptor(qrSecret)

			// Attempt decryption
			decryptedData, err := decryptor.DecryptServiceData(encryptedData)

			if tc.shouldSucceed {
				if err != nil {
					t.Fatalf("Expected decryption to succeed, but got error: %v", err)
				}

				// Verify expected plaintext
				expectedPlaintext, _ := hex.DecodeString(tc.expectedPlaintext)
				if !bytes.Equal(decryptedData, expectedPlaintext) {
					t.Errorf("Decrypted data mismatch.\nExpected: %x\nActual:   %x", expectedPlaintext, decryptedData)
				}

				// Parse decrypted data
				nonce, routingID, tunnelService, _, parseErr := ParseDecryptedServiceData(decryptedData)
				if parseErr != nil {
					t.Fatalf("Failed to parse decrypted data: %v", parseErr)
				}

				// Verify parsed fields
				expectedNonce, _ := hex.DecodeString(tc.expectedNonce)
				if !bytes.Equal(nonce, expectedNonce) {
					t.Errorf("Nonce mismatch.\nExpected: %x\nActual:   %x", expectedNonce, nonce)
				}

				expectedRoutingID, _ := hex.DecodeString(tc.expectedRoutingID)
				if !bytes.Equal(routingID, expectedRoutingID) {
					t.Errorf("Routing ID mismatch.\nExpected: %x\nActual:   %x", expectedRoutingID, routingID)
				}

				expectedTunnelService, _ := hex.DecodeString(tc.expectedTunnelService)
				if !bytes.Equal(tunnelService, expectedTunnelService) {
					t.Errorf("Tunnel Service mismatch.\nExpected: %x\nActual:   %x", expectedTunnelService, tunnelService)
				}

			} else {
				if err == nil {
					t.Errorf("Expected decryption to fail, but it succeeded with result: %x", decryptedData)
				}
			}
		})
	}
}

// TestHKDFKeyDerivation tests the HKDF key derivation functionality
func TestHKDFKeyDerivation(t *testing.T) {
	testCases := []struct {
		name      string
		qrSecret  string
		purpose   keyPurpose
		expectedKeyPrefix string  // First 8 bytes for verification
	}{
		{
			name:      "EID key derivation synthetic case 1",
			qrSecret:  "3e3bb1c00f37e7380280f2b1f2fc3846",
			purpose:   keyPurposeEIDKey,
			expectedKeyPrefix: "2ee8efb7d730cebf",  // From synthetic test vector generation
		},
		{
			name:      "EID key derivation synthetic case 2", 
			qrSecret:  "f260d8c9c60ce46fe38aa666fba688ed",
			purpose:   keyPurposeEIDKey,
			expectedKeyPrefix: "74939221f28dbe5a",  // From synthetic test vector generation
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Decode hex strings
			qrSecret, err := hex.DecodeString(tc.qrSecret)
			if err != nil {
				t.Fatalf("Failed to decode QR secret: %v", err)
			}

			// Create decryptor and derive key
			decryptor := NewCableV2Decryptor(qrSecret)
			var eidKey [CableV2EIDKeyLength]byte
			err = decryptor.derive(eidKey[:], qrSecret, nil, tc.purpose)
			if err != nil {
				t.Fatalf("Key derivation failed: %v", err)
			}

			// Verify key prefix (first 8 bytes)
			expectedPrefix, _ := hex.DecodeString(tc.expectedKeyPrefix)
			actualPrefix := eidKey[:8]

			if !bytes.Equal(actualPrefix, expectedPrefix) {
				t.Errorf("Key prefix mismatch.\nExpected: %x\nActual:   %x", expectedPrefix, actualPrefix)
			}
		})
	}
}

// TestTrialDecryptFunction tests the trialDecrypt function directly
func TestTrialDecryptFunction(t *testing.T) {
	testCases := []struct {
		name         string
		qrSecret     string
		serviceData  string
		shouldSucceed bool
		expectedFirstByte byte  // Expected first byte of plaintext (should be 0)
	}{
		{
			name:         "Valid service data should decrypt",
			qrSecret:     "3e3bb1c00f37e7380280f2b1f2fc3846", 
			serviceData:  "5fe6149e9950f5957a92a0ebc8c1766d80969202",
			shouldSucceed: true,
			expectedFirstByte: 0x00,
		},
		{
			name:         "Invalid HMAC should fail",
			qrSecret:     "3e3bb1c00f37e7380280f2b1f2fc3846",
			serviceData:  "5fe6149e9950f5957a92a0ebc8c1766dffffffff",  // Corrupted HMAC
			shouldSucceed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			qrSecret, _ := hex.DecodeString(tc.qrSecret)
			serviceData, _ := hex.DecodeString(tc.serviceData)

			decryptor := NewCableV2Decryptor(qrSecret)
			var eidKey [CableV2EIDKeyLength]byte
			decryptor.derive(eidKey[:], qrSecret, nil, keyPurposeEIDKey)

			// Test trialDecrypt
			plaintext, success := decryptor.trialDecrypt(&eidKey, serviceData)

			if tc.shouldSucceed {
				if !success {
					t.Errorf("Expected trialDecrypt to succeed, but it failed")
				}
				if plaintext[0] != tc.expectedFirstByte {
					t.Errorf("Expected first byte %02x, got %02x", tc.expectedFirstByte, plaintext[0])
				}
			} else {
				if success {
					t.Errorf("Expected trialDecrypt to fail, but it succeeded")
				}
			}
		})
	}
}

// TestUnpackDecryptedAdvert tests the UnpackDecryptedAdvert function
func TestUnpackDecryptedAdvert(t *testing.T) {
	// Test data from synthetic test vector case 1
	plaintextHex := "00b89c04c7dc93c57a1ceb801be00000"
	plaintextBytes, _ := hex.DecodeString(plaintextHex)
	
	var plaintext [CableV2PlaintextLength]byte
	copy(plaintext[:], plaintextBytes)

	nonce, routingID, encodedTunnelDomain := UnpackDecryptedAdvert(plaintext)

	// Verify nonce (10 bytes)
	expectedNonce := "b89c04c7dc93c57a1ceb"
	if hex.EncodeToString(nonce[:]) != expectedNonce {
		t.Errorf("Nonce mismatch.\nExpected: %s\nActual:   %x", expectedNonce, nonce)
	}

	// Verify routing ID (3 bytes)
	expectedRoutingID := "801be0"
	if hex.EncodeToString(routingID[:]) != expectedRoutingID {
		t.Errorf("Routing ID mismatch.\nExpected: %s\nActual:   %x", expectedRoutingID, routingID)
	}

	// Verify encoded tunnel domain (uint16, little-endian)
	expectedDomain := uint16(0x0000)  // 0x0000 in little-endian
	if encodedTunnelDomain != expectedDomain {
		t.Errorf("Encoded tunnel domain mismatch.\nExpected: %d\nActual:   %d", expectedDomain, encodedTunnelDomain)
	}
}

// TestReservedBitsValidation tests the reserved bits validation
func TestReservedBitsValidation(t *testing.T) {
	decryptor := NewCableV2Decryptor([]byte("dummy"))

	testCases := []struct {
		name          string
		firstByte     byte
		shouldBeValid bool
	}{
		{"Valid reserved bits (0x00)", 0x00, true},
		{"Invalid reserved bits (0x01)", 0x01, false},
		{"Invalid reserved bits (0xFF)", 0xFF, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var plaintext [CableV2PlaintextLength]byte
			plaintext[0] = tc.firstByte

			isValid := decryptor.reservedBitsAreZero(plaintext)
			if isValid != tc.shouldBeValid {
				t.Errorf("Expected validation result %v, got %v", tc.shouldBeValid, isValid)
			}
		})
	}
}