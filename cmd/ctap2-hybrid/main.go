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

	// Step 2: Create BLE scanner 
	bleScanner, err := ble.NewScanner(qrData.QRSecret)
	if err != nil {
		return fmt.Errorf("failed to create BLE scanner: %w", err)
	}

	// Step 3: Wait for BLE advertisement from smartphone
	fmt.Println("Waiting for smartphone to advertise after QR scan...")
	
	// Wait for BLE advertisement with tunnel service information
	tunnelInfo, err := bleScanner.WaitForTunnelAdvertisement(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive tunnel advertisement: %w", err)
	}
	
	fmt.Printf("Received tunnel service information:\n")
	fmt.Printf("  Tunnel URL: %s\n", tunnelInfo.TunnelURL)
	fmt.Printf("  Routing ID: %x\n", tunnelInfo.RoutingID)
	fmt.Printf("  Tunnel ID: %x\n", tunnelInfo.TunnelID)
	fmt.Printf("  Additional Data: %x\n", tunnelInfo.AdditionalData)
	
	// Step 4: Setup tunnel service with information from BLE advertisement
	tunnelClient, err := tunnel.NewClient(tunnelInfo.TunnelURL, qrData.PrivateKey, qrData.PublicKey, qrData.QRSecret)
	if err != nil {
		return fmt.Errorf("failed to create tunnel client: %w", err)
	}
	
	// Update tunnel client with advertisement information
	tunnelClient.SetTunnelInfo(tunnelInfo.RoutingID, tunnelInfo.TunnelID)
	
	fmt.Println("Tunnel service information received, but not connecting (as requested)")
	fmt.Println("Implementation complete - ready for actual tunnel connection")
	
	// TODO: Implement actual tunnel connection and CTAP2 message handling
	// This would involve:
	// 1. conn, err := tunnelClient.WaitForConnection(ctx)
	// 2. handler := ctap2.NewHandler(conn, transport.OutputFile)
	// 3. attestationData, err := handler.HandleAuthentication(ctx)
	// 4. attestation.SaveToFile(attestationData, transport.OutputFile)
	
	return nil
}