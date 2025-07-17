package ble

import (
	"context"
	"fmt"
	"log"
)

// Advertiser handles BLE advertising for CTAP2 hybrid transport
type Advertiser struct {
	qrSecret []byte
	running  bool
}

// NewAdvertiser creates a new BLE advertiser
func NewAdvertiser(qrSecret []byte) (*Advertiser, error) {
	if len(qrSecret) != 32 {
		return nil, fmt.Errorf("QR secret must be 32 bytes, got %d", len(qrSecret))
	}

	return &Advertiser{
		qrSecret: qrSecret,
		running:  false,
	}, nil
}

// Start begins BLE advertising
func (a *Advertiser) Start(ctx context.Context) error {
	if a.running {
		return fmt.Errorf("advertiser is already running")
	}

	a.running = true
	log.Println("BLE advertising started (stub implementation)")
	log.Printf("QR Secret: %x", a.qrSecret)

	// TODO: Implement actual BLE advertising
	// For now, just log that we're advertising
	go func() {
		<-ctx.Done()
		a.running = false
		log.Println("BLE advertising stopped")
	}()

	return nil
}

// Stop stops BLE advertising
func (a *Advertiser) Stop() {
	if a.running {
		a.running = false
		log.Println("BLE advertising stopped")
	}
}

// IsRunning returns whether the advertiser is currently running
func (a *Advertiser) IsRunning() bool {
	return a.running
}