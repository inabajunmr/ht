package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

	// Setup log file for non-QR output
	if err := setupLogFile(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup log file: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Handle interrupt signals with proper shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, initiating shutdown...", sig)
		cancel()
		
		// Give some time for graceful shutdown, then force exit
		go func() {
			time.Sleep(3 * time.Second)
			log.Printf("Force exit after 3 seconds")
			os.Exit(1)
		}()
	}()

	// Initialize CTAP2 hybrid transport
	transport := &ctap2.HybridTransport{
		TunnelURL:  *tunnelURL,
		OutputFile: *outputFile,
	}

	// Start the hybrid transport process
	log.Printf("Starting hybrid transport with timeout: %v", *timeout)
	
	// Ensure log file is properly closed on exit
	defer func() {
		if logFileHandle != nil {
			log.Printf("=== CTAP2 Hybrid Transport Log Ended ===")
			log.Printf("Timestamp: %s", time.Now().Format(time.RFC3339))
			logFileHandle.Close()
		}
	}()
	
	if err := runHybridTransport(ctx, transport); err != nil {
		if err == context.DeadlineExceeded {
			log.Printf("Operation timed out after %v", *timeout)
			return
		} else if err == context.Canceled {
			log.Printf("Operation cancelled by user")
			return
		} else {
			log.Printf("Error: %v", err)
			os.Exit(1)
		}
	}
	log.Printf("Hybrid transport completed successfully")
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
	log.Println("Waiting for smartphone to advertise after QR scan...")
	
	// Check if context is already cancelled before starting scan
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	
	// Wait for BLE advertisement with tunnel service information
	tunnelInfo, err := bleScanner.WaitForTunnelAdvertisement(ctx)
	if err != nil {
		if err == context.DeadlineExceeded {
			log.Printf("Timeout waiting for BLE advertisement")
			return err
		} else if err == context.Canceled {
			log.Printf("BLE scan cancelled")
			return err
		}
		return fmt.Errorf("failed to receive tunnel advertisement: %w", err)
	}
	
	log.Printf("Received tunnel service information:")
	log.Printf("  Tunnel URL: %s", tunnelInfo.TunnelURL)
	log.Printf("  Connection Nonce: %x", tunnelInfo.ConnectionNonce)
	log.Printf("  Routing ID: %x", tunnelInfo.RoutingID)
	log.Printf("  Tunnel Service ID: %x", tunnelInfo.TunnelServiceID)
	log.Printf("  Encoded Tunnel Domain: %d", tunnelInfo.EncodedTunnelDomain)
	log.Printf("  Additional Data: %x", tunnelInfo.AdditionalData)
	
	// Step 4: Setup tunnel service with information from BLE advertisement
	tunnelClient, err := tunnel.NewClient(tunnelInfo.TunnelURL, qrData.PrivateKey, qrData.PublicKey, qrData.QRSecret)
	if err != nil {
		return fmt.Errorf("failed to create tunnel client: %w", err)
	}
	
	// Update tunnel client with advertisement information
	tunnelClient.SetTunnelInfo(tunnelInfo.RoutingID, tunnelInfo.ConnectionNonce)
	
	log.Println("Tunnel service information received, but not connecting (as requested)")
	log.Println("Implementation complete - ready for actual tunnel connection")
	
	// TODO: Implement actual tunnel connection and CTAP2 message handling
	// This would involve:
	// 1. conn, err := tunnelClient.WaitForConnection(ctx)
	// 2. handler := ctap2.NewHandler(conn, transport.OutputFile)
	// 3. attestationData, err := handler.HandleAuthentication(ctx)
	// 4. attestation.SaveToFile(attestationData, transport.OutputFile)
	
	return nil
}

// Global log file handle for proper cleanup
var logFileHandle *os.File

// setupLogFile creates log directory and redirects log output to log/latest.log
func setupLogFile() error {
	// Create log directory if it doesn't exist
	logDir := "log"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create/truncate log file
	logFile := filepath.Join(logDir, "latest.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}

	// Store file handle globally for cleanup
	logFileHandle = file

	// Create multi-writer to write to both file and stdout for QR code
	multiWriter := io.MultiWriter(file, os.Stdout)
	log.SetOutput(multiWriter)

	// Write initial log header
	log.Printf("=== CTAP2 Hybrid Transport Log Started ===")
	log.Printf("Log file: %s", logFile)
	log.Printf("Timestamp: %s", time.Now().Format(time.RFC3339))
	log.Printf("Timeout: %v", time.Duration(0)) // Will be updated in main
	log.Printf("============================================")

	fmt.Printf("Log file created: %s\n", logFile)
	return nil
}