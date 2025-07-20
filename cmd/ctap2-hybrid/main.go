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
	// Note: ConnectionNonce is the 10-byte nonce from BLE, but SetTunnelInfo expects tunnelID
	// For caBLE v2, we use the ConnectionNonce as tunnel identifier
	tunnelClient.SetTunnelInfo(tunnelInfo.RoutingID, tunnelInfo.ConnectionNonce)
	
	log.Printf("Tunnel service information received, attempting connection...")
	
	// Step 5: Establish tunnel connection
	log.Printf("Connecting to tunnel service...")
	conn, err := tunnelClient.WaitForConnection(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to tunnel service: %w", err)
	}
	defer conn.Close()
	
	log.Printf("Tunnel connection established successfully")
	
	// Step 6: Listen for incoming messages from smartphone
	log.Printf("Listening for messages from smartphone...")
	for {
		select {
		case <-ctx.Done():
			log.Printf("Context cancelled, stopping message listener")
			return ctx.Err()
		default:
			// Read message with timeout
			message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Error reading message: %v", err)
				// Continue listening for more messages
				continue
			}
			
			// Log received data
			log.Printf("=== RECEIVED MESSAGE FROM SMARTPHONE ===")
			log.Printf("Message length: %d bytes", len(message))
			log.Printf("Message (hex): %x", message)
			log.Printf("Message (raw): %v", message)
			
			// Try to parse as string if printable
			if isPrintableASCII(message) {
				log.Printf("Message (string): %s", string(message))
			}
			
			log.Printf("======================================")
			
			// Parse and process as CTAP2 message
			if err := processCTAP2Message(conn, message); err != nil {
				log.Printf("Error processing CTAP2 message: %v", err)
			}
		}
	}
	return nil
}

// isPrintableASCII checks if a byte slice contains only printable ASCII characters
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return len(data) > 0
}

// processCTAP2Message processes a received message as CTAP2 protocol
func processCTAP2Message(conn *tunnel.Connection, rawMessage []byte) error {
	log.Printf("Processing message as CTAP2 protocol...")
	
	// Parse the message
	ctap2Message, err := ctap2.ParseCTAP2Message(rawMessage)
	if err != nil {
		log.Printf("Failed to parse CTAP2 message: %v", err)
		return fmt.Errorf("CTAP2 parsing failed: %w", err)
	}
	
	// Create CTAP2 handler
	handler := ctap2.NewHandler(conn, "attestation.json")
	
	// Process the message and generate response
	response, err := handler.ProcessCTAP2Message(ctap2Message)
	if err != nil {
		log.Printf("Failed to process CTAP2 message: %v", err)
		return fmt.Errorf("CTAP2 processing failed: %w", err)
	}
	
	// Send response back to smartphone
	if len(response) > 0 {
		log.Printf("Sending CTAP2 response (%d bytes): %x", len(response), response)
		
		err = conn.WriteMessage(response)
		if err != nil {
			log.Printf("Failed to send CTAP2 response: %v", err)
			return fmt.Errorf("failed to send response: %w", err)
		}
		
		log.Printf("CTAP2 response sent successfully")
	} else {
		log.Printf("No response data to send")
	}
	
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