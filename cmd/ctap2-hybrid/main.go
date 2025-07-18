package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ctap2-hybrid-transport/pkg/attestation"
	"ctap2-hybrid-transport/pkg/ble"
	"ctap2-hybrid-transport/pkg/ctap2"
	"ctap2-hybrid-transport/pkg/qrcode"
	"ctap2-hybrid-transport/pkg/tunnel"
)

func main() {
	var (
		outputFile = flag.String("output", "attestation.json", "Output file for attestation")
		tunnelURL  = flag.String("tunnel", "wss://cableconnect.googleapis.com/v1/connect", "Tunnel service URL")
		timeout    = flag.Duration("timeout", 5*time.Minute, "Operation timeout")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Handle interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	// Initialize CTAP2 hybrid transport
	transport := &ctap2.HybridTransport{
		TunnelURL:  *tunnelURL,
		OutputFile: *outputFile,
	}

	// Start the hybrid transport process
	if err := runHybridTransport(ctx, transport); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func runHybridTransport(ctx context.Context, transport *ctap2.HybridTransport) error {
	// Step 1: Generate and display QR code
	qrData, err := qrcode.GenerateQRData()
	if err != nil {
		return fmt.Errorf("failed to generate QR data: %w", err)
	}

	if err := qrcode.DisplayQR(qrData); err != nil {
		return fmt.Errorf("failed to display QR code: %w", err)
	}

	// Step 2: Start BLE scanning for CTAP2 hybrid transport
	bleScanner, err := ble.NewScanner(qrData.QRSecret)
	if err != nil {
		return fmt.Errorf("failed to create BLE scanner: %w", err)
	}

	if err := bleScanner.StartScanning(ctx); err != nil {
		return fmt.Errorf("failed to start BLE scanning: %w", err)
	}
	defer bleScanner.StopScanning()

	// Step 3: Setup tunnel service
	tunnelClient, err := tunnel.NewClient(qrData.TunnelURL, qrData.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create tunnel client: %w", err)
	}

	// Step 4: Wait for connection and handle CTAP2 messages
	fmt.Println("Waiting for authenticator connection...")
	
	conn, err := tunnelClient.WaitForConnection(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish tunnel connection: %w", err)
	}
	defer conn.Close()

	// Step 5: Handle CTAP2 protocol
	handler := ctap2.NewHandler(conn, transport.OutputFile)
	
	attestationData, err := handler.HandleAuthentication(ctx)
	if err != nil {
		return fmt.Errorf("failed to handle authentication: %w", err)
	}

	// Step 6: Save attestation
	if err := attestation.SaveToFile(attestationData, transport.OutputFile); err != nil {
		return fmt.Errorf("failed to save attestation: %w", err)
	}

	fmt.Printf("Attestation saved to: %s\n", transport.OutputFile)
	return nil
}