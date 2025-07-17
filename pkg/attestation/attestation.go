package attestation

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"ctap2-hybrid-transport/pkg/ctap2"
)

// SaveToFile saves attestation data to a JSON file
func SaveToFile(attestationData *ctap2.AttestationData, filename string) error {
	log.Printf("Saving attestation data to: %s", filename)

	// Convert to JSON
	jsonData, err := json.MarshalIndent(attestationData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write attestation file: %w", err)
	}

	log.Printf("Attestation data saved successfully to: %s", filename)
	return nil
}

// LoadFromFile loads attestation data from a JSON file
func LoadFromFile(filename string) (*ctap2.AttestationData, error) {
	log.Printf("Loading attestation data from: %s", filename)

	// Read file
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file: %w", err)
	}

	// Parse JSON
	var attestationData ctap2.AttestationData
	if err := json.Unmarshal(jsonData, &attestationData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation data: %w", err)
	}

	log.Printf("Attestation data loaded successfully from: %s", filename)
	return &attestationData, nil
}

// ValidateAttestationData validates the attestation data
func ValidateAttestationData(attestationData *ctap2.AttestationData) error {
	if len(attestationData.RequestID) == 0 {
		return fmt.Errorf("request ID cannot be empty")
	}

	if attestationData.Timestamp.IsZero() {
		return fmt.Errorf("timestamp cannot be zero")
	}

	if attestationData.AttestationObject == nil {
		return fmt.Errorf("attestation object cannot be nil")
	}

	if len(attestationData.ClientDataJSON) == 0 {
		return fmt.Errorf("client data JSON cannot be empty")
	}

	return nil
}