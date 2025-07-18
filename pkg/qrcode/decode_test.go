package qrcode

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// digitDecode is the reverse of digitEncode
func digitDecode(digitString string) ([]byte, error) {
	const chunkSize = 7
	const chunkDigits = 17
	
	var result []byte
	
	// Process full chunks
	for len(digitString) >= chunkDigits {
		chunkStr := digitString[:chunkDigits]
		digitString = digitString[chunkDigits:]
		
		// Convert to uint64
		val, err := strconv.ParseUint(chunkStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chunk %s: %w", chunkStr, err)
		}
		
		// Convert to little endian bytes
		var chunk [8]byte
		binary.LittleEndian.PutUint64(chunk[:], val)
		
		// Append first 7 bytes
		result = append(result, chunk[:chunkSize]...)
	}
	
	// Handle remaining digits
	if len(digitString) > 0 {
		// partialChunkDigits lookup table
		partialChunkDigits := map[int]int{
			15: 6, 13: 5, 10: 4, 8: 3, 5: 2, 3: 1, 0: 0,
		}
		
		expectedLen := -1
		for digits, length := range partialChunkDigits {
			if len(digitString) == digits {
				expectedLen = length
				break
			}
		}
		
		if expectedLen == -1 {
			return nil, fmt.Errorf("unexpected remaining digits length: %d", len(digitString))
		}
		
		// Convert to uint64
		val, err := strconv.ParseUint(digitString, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse remaining chunk %s: %w", digitString, err)
		}
		
		// Convert to little endian bytes
		var chunk [8]byte
		binary.LittleEndian.PutUint64(chunk[:], val)
		
		// Append expected length
		result = append(result, chunk[:expectedLen]...)
	}
	
	return result, nil
}

// parseCBORMap manually parses a CBOR map to extract key-value pairs
func parseCBORMap(data []byte) (map[int]interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty CBOR data")
	}
	
	// Check if it's a map
	if data[0] < 0xa0 || data[0] > 0xb7 {
		return nil, fmt.Errorf("not a CBOR map: first byte is 0x%02x", data[0])
	}
	
	mapSize := int(data[0] - 0xa0)
	fmt.Printf("CBOR Map with %d elements\n", mapSize)
	
	result := make(map[int]interface{})
	pos := 1
	
	for i := 0; i < mapSize; i++ {
		if pos >= len(data) {
			return nil, fmt.Errorf("unexpected end of data at position %d", pos)
		}
		
		// Parse key (should be integer)
		var key int
		if data[pos] == 0x19 { // 2-byte integer follows
			key = int(binary.BigEndian.Uint16(data[pos+1:pos+3]))
			pos += 3
		} else {
			key = int(data[pos])
			pos++
		}
		
		// Parse value based on type
		if pos >= len(data) {
			return nil, fmt.Errorf("unexpected end of data at value position %d", pos)
		}
		
		majorType := data[pos] >> 5
		additionalInfo := data[pos] & 0x1f
		
		fmt.Printf("  Element %d: key=%d, value_byte=0x%02x, major_type=%d, additional_info=%d\n", 
			i, key, data[pos], majorType, additionalInfo)
		
		switch majorType {
		case 0: // Positive integer
			if additionalInfo < 24 {
				result[key] = int(additionalInfo)
				pos++
			} else if additionalInfo == 24 {
				result[key] = int(data[pos+1])
				pos += 2
			} else if additionalInfo == 25 {
				result[key] = int(binary.BigEndian.Uint16(data[pos+1:pos+3]))
				pos += 3
			} else if additionalInfo == 26 {
				result[key] = int(binary.BigEndian.Uint32(data[pos+1:pos+5]))
				pos += 5
			} else if additionalInfo == 27 {
				result[key] = int(binary.BigEndian.Uint64(data[pos+1:pos+9]))
				pos += 9
			}
		case 1: // Negative integer
			// Negative integers are encoded as -1 - n where n is the encoded value
			var n int
			if additionalInfo < 24 {
				n = int(additionalInfo)
				pos++
			} else if additionalInfo == 24 {
				n = int(data[pos+1])
				pos += 2
			} else if additionalInfo == 25 {
				n = int(binary.BigEndian.Uint16(data[pos+1:pos+3]))
				pos += 3
			} else if additionalInfo == 26 {
				n = int(binary.BigEndian.Uint32(data[pos+1:pos+5]))
				pos += 5
			} else if additionalInfo == 27 {
				n = int(binary.BigEndian.Uint64(data[pos+1:pos+9]))
				pos += 9
			}
			result[key] = -1 - n
		case 2: // Byte string
			var length int
			if additionalInfo < 24 {
				length = int(additionalInfo)
				pos++
			} else if additionalInfo == 24 {
				length = int(data[pos+1])
				pos += 2
			} else if additionalInfo == 25 {
				length = int(binary.BigEndian.Uint16(data[pos+1:pos+3]))
				pos += 3
			}
			
			if pos+length > len(data) {
				return nil, fmt.Errorf("byte string length extends beyond data")
			}
			
			result[key] = data[pos:pos+length]
			pos += length
		case 3: // Text string
			var length int
			if additionalInfo < 24 {
				length = int(additionalInfo)
				pos++
			} else if additionalInfo == 24 {
				length = int(data[pos+1])
				pos += 2
			} else if additionalInfo == 25 {
				length = int(binary.BigEndian.Uint16(data[pos+1:pos+3]))
				pos += 3
			}
			
			if pos+length > len(data) {
				return nil, fmt.Errorf("string length extends beyond data")
			}
			
			result[key] = string(data[pos:pos+length])
			pos += length
		case 7: // Floats, simple values
			if additionalInfo == 21 { // true
				result[key] = true
				pos++
			} else if additionalInfo == 20 { // false
				result[key] = false
				pos++
			} else if additionalInfo == 31 { // undefined/null or other
				// Skip GREASE values
				result[key] = nil
				if pos+1 < len(data) && data[pos+1] == 0xff && pos+2 < len(data) && data[pos+2] == 0x00 {
					pos += 3 // Skip 0xff 0x00
				} else {
					pos++
				}
			} else {
				return nil, fmt.Errorf("unsupported simple value: %d", additionalInfo)
			}
		default:
			return nil, fmt.Errorf("unsupported CBOR major type: %d", majorType)
		}
	}
	
	return result, nil
}

func TestDecodeBrowserQRCode(t *testing.T) {
	// Browser generated QR code
	browserQR := "FIDO:/164256176516630141297853122626219945748359380652102059895513187047676334729158906597767563397436255501466762135855516730075336766520323071777744305390338107096654083076"
	
	// Remove FIDO:/ prefix
	digitString := strings.TrimPrefix(browserQR, "FIDO:/")
	
	// Decode digit string to bytes
	cborData, err := digitDecode(digitString)
	if err != nil {
		t.Fatalf("Failed to decode digit string: %v", err)
	}
	
	t.Logf("Decoded CBOR data length: %d bytes", len(cborData))
	t.Logf("Decoded CBOR data (hex): %x", cborData)
	
	// Parse CBOR map
	cborMap, err := parseCBORMap(cborData)
	if err != nil {
		t.Fatalf("Failed to parse CBOR map: %v", err)
	}
	
	// Display parsed structure
	t.Logf("Parsed CBOR map:")
	for key, value := range cborMap {
		switch v := value.(type) {
		case []byte:
			t.Logf("  Key %d: %x (%d bytes)", key, v, len(v))
		case string:
			t.Logf("  Key %d: %s", key, v)
		case bool:
			t.Logf("  Key %d: %t", key, v)
		default:
			t.Logf("  Key %d: %v", key, v)
		}
	}
}

func TestCompareWithOurImplementation(t *testing.T) {
	// Generate our QR code
	qrData, err := GenerateQRData()
	if err != nil {
		t.Fatalf("Failed to generate QR data: %v", err)
	}
	
	// Encode with our implementation
	ourURL, err := encodeCableV2URL(qrData)
	if err != nil {
		t.Fatalf("Failed to encode our URL: %v", err)
	}
	
	// Decode our URL
	ourDigitString := strings.TrimPrefix(ourURL, "FIDO:/")
	ourCBORData, err := digitDecode(ourDigitString)
	if err != nil {
		t.Fatalf("Failed to decode our digit string: %v", err)
	}
	
	// Parse our CBOR map
	ourCBORMap, err := parseCBORMap(ourCBORData)
	if err != nil {
		t.Fatalf("Failed to parse our CBOR map: %v", err)
	}
	
	t.Logf("Our implementation:")
	t.Logf("  URL: %s", ourURL)
	t.Logf("  URL Length: %d", len(ourURL))
	t.Logf("  CBOR data length: %d bytes", len(ourCBORData))
	t.Logf("  CBOR data (hex): %x", ourCBORData)
	
	t.Logf("Our CBOR map:")
	for key, value := range ourCBORMap {
		switch v := value.(type) {
		case []byte:
			t.Logf("  Key %d: %x (%d bytes)", key, v, len(v))
		case string:
			t.Logf("  Key %d: %s", key, v)
		case bool:
			t.Logf("  Key %d: %t", key, v)
		default:
			t.Logf("  Key %d: %v", key, v)
		}
	}
	
	// Compare key structures
	expectedKeys := []int{0, 1, 2, 3, 4, 5}
	for _, key := range expectedKeys {
		if _, exists := ourCBORMap[key]; !exists {
			t.Errorf("Missing key %d in our implementation", key)
		}
	}
}