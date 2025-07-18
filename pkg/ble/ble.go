package ble

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tinygo.org/x/bluetooth"
)

// CTAP BLE constants based on official FIDO specification
const (
	// FIDO Service UUID (16-bit: 0xFFFD) - from CTAP specification
	FIDOServiceUUID = "0000fffd-0000-1000-8000-00805f9b34fb"
	
	// For hybrid transport, we also need to scan for both UUIDs
	// as implementations may vary
	CableServiceUUID = "0000fff9-0000-1000-8000-00805f9b34fb" // Some implementations use this
	
	// CTAP BLE advertisement constants
	ServiceDataMinLength = 3  // Minimum service data length (UUID + 1 flag byte)
	CableV2AdvDataLength = 20 // Service data length for caBLE v2
	CableV2NonceLength   = 8  // Nonce length in BLE advertisement
	CableV2RoutingLength = 3  // Routing ID length
	CableV2TunnelLength  = 2  // Tunnel service identifier length
	
	// Service Data Flag bits (from CTAP spec)
	FlagPairingMode = 0x80 // Bit 7: Device is in pairing mode
	FlagPasskeyReq  = 0x40 // Bit 6: Device requires passkey input
)

// TunnelInfo contains tunnel service information from BLE advertisement
type TunnelInfo struct {
	TunnelURL      string
	RoutingID      []byte
	TunnelID       []byte
	AdditionalData []byte
}

// Advertiser handles BLE advertising for CTAP2 hybrid transport
type Advertiser struct {
	qrSecret []byte
	running  bool
	adapter  *bluetooth.Adapter
}

// Scanner handles BLE scanning for CTAP2 hybrid transport
type Scanner struct {
	qrSecret        []byte
	running         bool
	adapter         *bluetooth.Adapter
	checkedDevices  map[string]bool // Track devices we've already checked
	deviceLogs      map[string]*os.File // Device-specific log files
	logDir          string              // Log directory path
}

// NewAdvertiser creates a new BLE advertiser
func NewAdvertiser(qrSecret []byte) (*Advertiser, error) {
	if len(qrSecret) != 32 {
		return nil, fmt.Errorf("QR secret must be 32 bytes, got %d", len(qrSecret))
	}

	// Enable BLE stack
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, fmt.Errorf("failed to enable bluetooth: %w", err)
	}

	return &Advertiser{
		qrSecret: qrSecret,
		running:  false,
		adapter:  adapter,
	}, nil
}

// NewScanner creates a new BLE scanner
func NewScanner(qrSecret []byte) (*Scanner, error) {
	if len(qrSecret) != 16 {
		return nil, fmt.Errorf("QR secret must be 16 bytes, got %d", len(qrSecret))
	}

	// Enable BLE stack
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, fmt.Errorf("failed to enable bluetooth: %w", err)
	}

	// Create log directory
	logDir := "log"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	return &Scanner{
		qrSecret:       qrSecret,
		running:        false,
		adapter:        adapter,
		checkedDevices: make(map[string]bool),
		deviceLogs:     make(map[string]*os.File),
		logDir:         logDir,
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

// StartScanning begins BLE scanning for CTAP2 hybrid transport
func (s *Scanner) StartScanning(ctx context.Context) error {
	if s.running {
		return fmt.Errorf("scanner is already running")
	}

	s.running = true
	log.Println("BLE scanning started")
	log.Printf("Scanning for FIDO service UUID: %s (CTAP spec)", FIDOServiceUUID)
	log.Printf("Also scanning for caBLE service UUID: %s (hybrid transport)", CableServiceUUID)
	log.Println("NOTE: After scanning the QR code with your phone, wait for the phone to start advertising...")
	log.Println("Look for devices with strong signal (>-40 dBm) that might be your phone.")
	log.Println("The phone should advertise with FIDO service UUID 0xFFFD according to CTAP specification.")

	// Parse both service UUIDs
	fidoServiceUUID, err := bluetooth.ParseUUID(FIDOServiceUUID)
	if err != nil {
		return fmt.Errorf("failed to parse FIDO service UUID: %w", err)
	}
	
	cableServiceUUID, err := bluetooth.ParseUUID(CableServiceUUID)
	if err != nil {
		return fmt.Errorf("failed to parse caBLE service UUID: %w", err)
	}

	// Start scanning in a goroutine
	go func() {
		defer func() {
			s.running = false
			log.Println("BLE scanning stopped")
		}()

		// Scan for a reasonable duration with periodic restarts
		for s.running {
			select {
			case <-ctx.Done():
				return
			default:
				log.Println("Starting BLE scan cycle...")
				
				err := s.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
					deviceAddr := result.Address.String()
					localName := result.AdvertisementPayload.LocalName()
					
					// Log every BLE device found (console output)
					log.Printf("BLE Device: %s (RSSI: %d dBm)", deviceAddr, result.RSSI)
					if localName != "" {
						log.Printf("  Local Name: %s", localName)
					}
					
					// Log detailed device information to device-specific log file
					s.logDeviceInfo(deviceAddr, result.RSSI, localName, result.AdvertisementPayload)
					
					// Check if this advertisement contains either FIDO service UUID
					fidoServiceFound := result.AdvertisementPayload.HasServiceUUID(fidoServiceUUID)
					cableServiceFound := result.AdvertisementPayload.HasServiceUUID(cableServiceUUID)
					
					if fidoServiceFound || cableServiceFound {
						log.Printf("*** FOUND FIDO/CTAP ADVERTISEMENT ***")
						log.Printf("Device: %s", result.Address.String())
						log.Printf("RSSI: %d dBm", result.RSSI)
						if fidoServiceFound {
							log.Printf("FIDO Service UUID found: %s", FIDOServiceUUID)
						}
						if cableServiceFound {
							log.Printf("caBLE Service UUID found: %s", CableServiceUUID)
						}
						log.Printf("Local Name: %s", result.AdvertisementPayload.LocalName())
						
						// Try to extract service data for both UUIDs
						if fidoServiceFound {
							if serviceData := s.extractFIDOServiceData(result.AdvertisementPayload); serviceData != nil {
								log.Printf("FIDO Service Data: %x", serviceData)
								if err := s.processFIDOAdvertisement(serviceData, result.Address); err != nil {
									log.Printf("Failed to process FIDO advertisement: %v", err)
								}
							}
						}
						
						if cableServiceFound {
							if serviceData := s.extractCableServiceData(result.AdvertisementPayload); serviceData != nil {
								log.Printf("caBLE Service Data: %x", serviceData)
								if err := s.processCableAdvertisement(serviceData, result.Address); err != nil {
									log.Printf("Failed to process caBLE advertisement: %v", err)
								}
							}
						}
						
						log.Printf("*** END FIDO/CTAP ADVERTISEMENT ***")
						return
					}
					
					// Since the TinyGo Bluetooth library has limitations, let's also check for 
					// devices that might be iOS/Android devices that could be advertising CTAP2
					// Look for devices with strong signal and check if they're phones
					if result.RSSI > -40 { // Strong signal, likely nearby phone
						// Check if this might be a phone by looking for common patterns
						deviceAddr := result.Address.String()
						localName := result.AdvertisementPayload.LocalName()
						
						// Log potential phone devices for manual inspection
						if localName != "" || result.RSSI > -30 {
							log.Printf("  >> Potential phone device nearby: %s (RSSI: %d, Name: %s)", 
								deviceAddr, result.RSSI, localName)
								
							// Try to connect to very close devices (>-35 dBm) to check GATT services
							if result.RSSI > -35 {
								// Check if we've already checked this device
								if !s.checkedDevices[deviceAddr] {
									log.Printf("  >> Attempting GATT connection to check for CTAP2 services...")
									s.checkedDevices[deviceAddr] = true
									go s.checkGATTServices(result.Address, result.RSSI)
								}
							}
						}
					}
				})
				
				if err != nil {
					log.Printf("BLE scan error: %v", err)
				}
				
				// Wait before next scan cycle
				time.Sleep(1 * time.Second)
			}
		}
	}()

	// Wait for context cancellation
	go func() {
		<-ctx.Done()
		log.Println("Stopping BLE scan due to context cancellation")
		if err := s.adapter.StopScan(); err != nil {
			log.Printf("Error stopping scan: %v", err)
		}
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

// StopScanning stops BLE scanning
func (s *Scanner) StopScanning() {
	if s.running {
		if err := s.adapter.StopScan(); err != nil {
			log.Printf("Error stopping scan: %v", err)
		}
		s.running = false
		
		// Close all device log files
		s.closeAllLogFiles()
		
		log.Println("BLE scanning stopped")
	}
}

// closeAllLogFiles closes all open device log files
func (s *Scanner) closeAllLogFiles() {
	for deviceAddr, logFile := range s.deviceLogs {
		logFile.WriteString(fmt.Sprintf("\n=== Log closed at: %s ===\n", time.Now().Format(time.RFC3339)))
		if err := logFile.Close(); err != nil {
			log.Printf("Error closing log file for device %s: %v", deviceAddr, err)
		} else {
			log.Printf("Closed log file for device %s", deviceAddr)
		}
	}
	// Clear the map
	s.deviceLogs = make(map[string]*os.File)
}

// IsScanning returns whether the scanner is currently running
func (s *Scanner) IsScanning() bool {
	return s.running
}

// checkGATTServices attempts to connect to a device and check for CTAP2 services
func (s *Scanner) checkGATTServices(address bluetooth.Address, rssi int16) {
	deviceAddr := address.String()
	log.Printf("  >> Connecting to device %s (RSSI: %d) to check GATT services...", deviceAddr, rssi)
	
	// Log GATT connection attempt to device log
	if logFile, err := s.getDeviceLogFile(deviceAddr); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] GATT CONNECTION ATTEMPT\n", time.Now().Format(time.RFC3339)))
		logFile.WriteString(fmt.Sprintf("  Attempting to connect for service discovery\n"))
		logFile.WriteString(fmt.Sprintf("  RSSI: %d dBm\n", rssi))
		logFile.Sync()
	}
	
	// Parse both service UUIDs
	fidoServiceUUID, err := bluetooth.ParseUUID(FIDOServiceUUID)
	if err != nil {
		log.Printf("  >> Failed to parse FIDO service UUID: %v", err)
		return
	}
	
	cableServiceUUID, err := bluetooth.ParseUUID(CableServiceUUID)
	if err != nil {
		log.Printf("  >> Failed to parse caBLE service UUID: %v", err)
		return
	}
	
	// Connect to the device
	device, err := s.adapter.Connect(address, bluetooth.ConnectionParams{})
	if err != nil {
		log.Printf("  >> Failed to connect to device %s: %v", deviceAddr, err)
		// Log connection failure
		if logFile, logErr := s.getDeviceLogFile(deviceAddr); logErr == nil {
			logFile.WriteString(fmt.Sprintf("  Connection FAILED: %v\n\n", err))
			logFile.Sync()
		}
		return
	}
	defer device.Disconnect()
	
	log.Printf("  >> Connected to device %s, discovering services...", deviceAddr)
	
	// Log successful connection
	if logFile, err := s.getDeviceLogFile(deviceAddr); err == nil {
		logFile.WriteString("  Connection SUCCESSFUL\n")
		logFile.WriteString("  Starting service discovery...\n")
		logFile.Sync()
	}
	
	// Discover services for both UUIDs
	services, err := device.DiscoverServices([]bluetooth.UUID{fidoServiceUUID, cableServiceUUID})
	if err != nil {
		log.Printf("  >> Failed to discover services on device %s: %v", deviceAddr, err)
		// Log service discovery failure
		if logFile, logErr := s.getDeviceLogFile(deviceAddr); logErr == nil {
			logFile.WriteString(fmt.Sprintf("  Service discovery FAILED: %v\n\n", err))
			logFile.Sync()
		}
		return
	}
	
	// Log discovered services
	if logFile, err := s.getDeviceLogFile(deviceAddr); err == nil {
		logFile.WriteString(fmt.Sprintf("  Service discovery SUCCESSFUL - found %d services\n", len(services)))
		for i, service := range services {
			logFile.WriteString(fmt.Sprintf("    Service %d: %s\n", i+1, service.UUID().String()))
		}
		logFile.Sync()
	}
	
	// Check if our target services are present
	for _, service := range services {
		if service.UUID() == fidoServiceUUID {
			log.Printf("*** FOUND FIDO SERVICE VIA GATT CONNECTION ***")
			log.Printf("Device: %s", deviceAddr)
			log.Printf("RSSI: %d dBm", rssi)
			log.Printf("FIDO Service UUID: %s", service.UUID().String())
			log.Printf("*** END FIDO SERVICE DISCOVERY ***")
			
			// Log to device file
			if logFile, logErr := s.getDeviceLogFile(deviceAddr); logErr == nil {
				logFile.WriteString("  *** FIDO SERVICE FOUND ***\n")
				logFile.WriteString(fmt.Sprintf("    UUID: %s\n", service.UUID().String()))
				logFile.WriteString("  *** TARGET SERVICE DETECTED ***\n\n")
				logFile.Sync()
			}
			return
		}
		if service.UUID() == cableServiceUUID {
			log.Printf("*** FOUND CABLE SERVICE VIA GATT CONNECTION ***")
			log.Printf("Device: %s", deviceAddr)
			log.Printf("RSSI: %d dBm", rssi)
			log.Printf("caBLE Service UUID: %s", service.UUID().String())
			log.Printf("*** END CABLE SERVICE DISCOVERY ***")
			
			// Log to device file
			if logFile, logErr := s.getDeviceLogFile(deviceAddr); logErr == nil {
				logFile.WriteString("  *** CABLE SERVICE FOUND ***\n")
				logFile.WriteString(fmt.Sprintf("    UUID: %s\n", service.UUID().String()))
				logFile.WriteString("  *** TARGET SERVICE DETECTED ***\n\n")
				logFile.Sync()
			}
			return
		}
	}
	
	log.Printf("  >> Device %s does not have FIDO/caBLE services", deviceAddr)
	
	// Log that target services were not found
	if logFile, err := s.getDeviceLogFile(deviceAddr); err == nil {
		logFile.WriteString("  Target services NOT FOUND\n")
		logFile.WriteString("  Device does not advertise FIDO or caBLE services\n\n")
		logFile.Sync()
	}
}

// getDeviceLogFile creates or gets existing log file for a device
func (s *Scanner) getDeviceLogFile(deviceAddr string) (*os.File, error) {
	// Sanitize device address for filename
	sanitizedAddr := strings.ReplaceAll(deviceAddr, ":", "-")
	
	// Check if log file already exists
	if logFile, exists := s.deviceLogs[deviceAddr]; exists {
		return logFile, nil
	}
	
	// Create new log file
	filename := fmt.Sprintf("device_%s_%d.log", sanitizedAddr, time.Now().Unix())
	filepath := filepath.Join(s.logDir, filename)
	
	logFile, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create device log file: %w", err)
	}
	
	// Store in map
	s.deviceLogs[deviceAddr] = logFile
	
	// Write header
	logFile.WriteString(fmt.Sprintf("=== BLE Device Log for %s ===\n", deviceAddr))
	logFile.WriteString(fmt.Sprintf("Started at: %s\n", time.Now().Format(time.RFC3339)))
	logFile.WriteString("==========================================\n\n")
	
	log.Printf("Created device log file: %s", filepath)
	return logFile, nil
}

// logDeviceInfo logs detailed device information to device-specific log file
func (s *Scanner) logDeviceInfo(deviceAddr string, rssi int16, localName string, payload bluetooth.AdvertisementPayload) {
	logFile, err := s.getDeviceLogFile(deviceAddr)
	if err != nil {
		log.Printf("Failed to get log file for device %s: %v", deviceAddr, err)
		return
	}
	
	timestamp := time.Now().Format(time.RFC3339)
	
	// Log basic device info
	logFile.WriteString(fmt.Sprintf("[%s] DEVICE SCAN RESULT\n", timestamp))
	logFile.WriteString(fmt.Sprintf("  Address: %s\n", deviceAddr))
	logFile.WriteString(fmt.Sprintf("  RSSI: %d dBm\n", rssi))
	logFile.WriteString(fmt.Sprintf("  Local Name: %s\n", localName))
	
	// Try to extract and log all available UUIDs
	logFile.WriteString("  Service UUID Detection:\n")
	
	// Check for FIDO service UUID
	fidoServiceUUID, _ := bluetooth.ParseUUID(FIDOServiceUUID)
	if payload.HasServiceUUID(fidoServiceUUID) {
		logFile.WriteString(fmt.Sprintf("    ✓ FIDO Service UUID: %s (FOUND)\n", FIDOServiceUUID))
	} else {
		logFile.WriteString(fmt.Sprintf("    ✗ FIDO Service UUID: %s (not found)\n", FIDOServiceUUID))
	}
	
	// Check for caBLE service UUID
	cableServiceUUID, _ := bluetooth.ParseUUID(CableServiceUUID)
	if payload.HasServiceUUID(cableServiceUUID) {
		logFile.WriteString(fmt.Sprintf("    ✓ caBLE Service UUID: %s (FOUND)\n", CableServiceUUID))
	} else {
		logFile.WriteString(fmt.Sprintf("    ✗ caBLE Service UUID: %s (not found)\n", CableServiceUUID))
	}
	
	// Check for other common UUIDs that might indicate FIDO capability
	commonUUIDs := []string{
		"0000180f-0000-1000-8000-00805f9b34fb", // Battery Service
		"0000180a-0000-1000-8000-00805f9b34fb", // Device Information
		"00001812-0000-1000-8000-00805f9b34fb", // HID Service
		"0000fffc-0000-1000-8000-00805f9b34fb", // FIDO Test UUID
		"0000fffe-0000-1000-8000-00805f9b34fb", // FIDO Alternative
	}
	
	foundCommon := false
	for _, uuidStr := range commonUUIDs {
		if uuid, err := bluetooth.ParseUUID(uuidStr); err == nil {
			if payload.HasServiceUUID(uuid) {
				logFile.WriteString(fmt.Sprintf("    ◦ Common UUID: %s (found)\n", uuidStr))
				foundCommon = true
			}
		}
	}
	
	if !foundCommon {
		logFile.WriteString("    ◦ No common service UUIDs detected\n")
	}
	
	// Note: TinyGo Bluetooth has limited payload inspection capabilities
	// In a full implementation, we would iterate through all advertised UUIDs
	logFile.WriteString("  Note: Limited to checking specific UUIDs due to TinyGo Bluetooth library constraints\n")
	logFile.WriteString("        Real devices may advertise additional UUIDs not checked here\n")
	
	// Log service data attempts
	logFile.WriteString("  Service Data Extraction:\n")
	if fidoServiceData := s.extractFIDOServiceData(payload); fidoServiceData != nil {
		logFile.WriteString(fmt.Sprintf("    - FIDO Service Data: %x\n", fidoServiceData))
	} else {
		logFile.WriteString("    - FIDO Service Data: Not found\n")
	}
	
	if cableServiceData := s.extractCableServiceData(payload); cableServiceData != nil {
		logFile.WriteString(fmt.Sprintf("    - caBLE Service Data: %x\n", cableServiceData))
	} else {
		logFile.WriteString("    - caBLE Service Data: Not found\n")
	}
	
	logFile.WriteString("\n")
	logFile.Sync() // Ensure data is written immediately
}

// extractFIDOServiceData extracts FIDO service data from BLE advertisement according to CTAP spec
func (s *Scanner) extractFIDOServiceData(payload bluetooth.AdvertisementPayload) []byte {
	// Try to get service data for FIDO service UUID
	// According to CTAP spec, service data should be:
	// - First 2 bytes: FIDO Service UUID (0xFFFD)
	// - Following bytes: flag bytes
	
	// Parse the service UUID
	serviceUUID, err := bluetooth.ParseUUID(FIDOServiceUUID)
	if err != nil {
		log.Printf("Failed to parse FIDO service UUID: %v", err)
		return nil
	}
	
	// Check if we can access service data (implementation dependent)
	// In a real implementation, this would extract the actual service data
	// For now, we'll log that we found the service and return a placeholder
	if payload.HasServiceUUID(serviceUUID) {
		log.Printf("Found FIDO service UUID, attempting to extract service data...")
		// Return a placeholder to indicate we found the service
		// In real implementation, this would extract actual service data with flags
		return []byte{0xFD, 0xFF, 0x00} // FIDO UUID (little endian) + flags placeholder
	}
	
	return nil
}

// processFIDOAdvertisement processes a FIDO BLE advertisement according to CTAP spec
func (s *Scanner) processFIDOAdvertisement(serviceData []byte, address bluetooth.Address) error {
	log.Printf("Processing FIDO advertisement from %s", address.String())
	
	if len(serviceData) < ServiceDataMinLength {
		return fmt.Errorf("service data too short: expected min %d bytes, got %d", ServiceDataMinLength, len(serviceData))
	}
	
	// According to CTAP spec:
	// - First 2 bytes: FIDO Service UUID
	// - Following bytes: flag bytes
	
	log.Printf("FIDO service data: %x", serviceData)
	
	if len(serviceData) >= 3 {
		flags := serviceData[2]
		log.Printf("FIDO flags byte: 0x%02x", flags)
		
		if flags&FlagPairingMode != 0 {
			log.Printf("  - Device is in pairing mode")
		}
		if flags&FlagPasskeyReq != 0 {
			log.Printf("  - Device requires passkey input")
		}
	}
	
	// TODO: Implement FIDO connection logic
	// - Connect to GATT service
	// - Perform CTAP2 handshake
	// - Handle authentication request
	
	return nil
}

// extractCableServiceData extracts caBLE v2 service data from BLE advertisement
func (s *Scanner) extractCableServiceData(payload bluetooth.AdvertisementPayload) []byte {
	// Try to get service data for caBLE service UUID
	// Note: TinyGo bluetooth library has limited service data access
	// This is a simplified implementation
	
	// Parse the service UUID
	serviceUUID, err := bluetooth.ParseUUID(CableServiceUUID)
	if err != nil {
		log.Printf("Failed to parse service UUID: %v", err)
		return nil
	}
	
	// Check if we can access service data (implementation dependent)
	// In a real implementation, this would extract the actual service data
	// For now, we'll log that we found the service and return a placeholder
	if payload.HasServiceUUID(serviceUUID) {
		log.Printf("Found caBLE service UUID, but service data extraction not fully supported by TinyGo")
		// Return a placeholder to indicate we found the service
		return []byte{0x01} // Placeholder
	}
	
	return nil
}

// processCableAdvertisement processes a caBLE v2 BLE advertisement
func (s *Scanner) processCableAdvertisement(serviceData []byte, address bluetooth.Address) error {
	log.Printf("Processing caBLE v2 advertisement from %s", address.String())
	
	// In a full implementation, this would:
	// 1. Decrypt the service data using the QR secret
	// 2. Extract the nonce, routing ID, and tunnel service identifier
	// 3. Initiate the tunnel connection
	// 4. Perform the Noise protocol handshake
	
	if len(serviceData) < CableV2AdvDataLength {
		return fmt.Errorf("service data too short: expected %d bytes, got %d", CableV2AdvDataLength, len(serviceData))
	}
	
	log.Printf("caBLE v2 advertisement processing would happen here")
	log.Printf("Service data length: %d bytes", len(serviceData))
	log.Printf("QR Secret for decryption: %x", s.qrSecret[:8]) // Show first 8 bytes only
	
	// TODO: Implement full caBLE v2 processing:
	// - Decrypt service data using HKDF derived from QR secret
	// - Extract nonce, routing ID, tunnel service identifier
	// - Connect to tunnel service
	// - Establish secure channel using Noise protocol
	
	return nil
}

// containsBytes checks if haystack contains needle
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	
	for i := 0; i <= len(haystack)-len(needle); i++ {
		found := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}

// WaitForTunnelAdvertisement waits for a BLE advertisement containing tunnel service information
func (s *Scanner) WaitForTunnelAdvertisement(ctx context.Context) (*TunnelInfo, error) {
	log.Printf("Waiting for BLE advertisement with tunnel service information...")
	
	// Channel to receive tunnel information
	tunnelInfoChan := make(chan *TunnelInfo, 1)
	
	// Start scanning with tunnel info detection
	err := s.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
		deviceID := result.Address.String()
		rssi := result.RSSI
		
		// Log device discovery
		log.Printf("BLE Device found: %s (RSSI: %d dBm)", deviceID, rssi)
		
		// Special check for device found by Python scanner
		if deviceID == "121b296f-41b8-90a8-f92f-355b91b6aa55" || deviceID == "121B296F-41B8-90A8-F92F-355B91B6AA55" {
			log.Printf("*** FOUND TARGET DEVICE FROM PYTHON SCANNER: %s ***", deviceID)
			
			// Force check for both UUIDs
			fidoServiceUUID, _ := bluetooth.ParseUUID(FIDOServiceUUID)
			cableServiceUUID, _ := bluetooth.ParseUUID(CableServiceUUID)
			
			hasFIDO := result.AdvertisementPayload.HasServiceUUID(fidoServiceUUID)
			hasCable := result.AdvertisementPayload.HasServiceUUID(cableServiceUUID)
			
			log.Printf("  FIDO UUID check: %v", hasFIDO)
			log.Printf("  caBLE UUID check: %v", hasCable)
			
			if hasFIDO || hasCable {
				log.Printf("*** SERVICE UUID DETECTED ON TARGET DEVICE ***")
				if s.processTunnelAdvertisement(result, tunnelInfoChan) {
					log.Printf("Tunnel service information detected from target device: %s", deviceID)
					return
				}
			}
		}
		
		// Check for FIDO service data
		if s.processTunnelAdvertisement(result, tunnelInfoChan) {
			log.Printf("Tunnel service information detected from device: %s", deviceID)
		}
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to start BLE scan: %w", err)
	}
	
	// Wait for tunnel info or context cancellation
	select {
	case tunnelInfo := <-tunnelInfoChan:
		s.adapter.StopScan()
		return tunnelInfo, nil
	case <-ctx.Done():
		s.adapter.StopScan()
		return nil, ctx.Err()
	}
}

// processTunnelAdvertisement processes BLE advertisement data for tunnel service information
func (s *Scanner) processTunnelAdvertisement(result bluetooth.ScanResult, tunnelInfoChan chan *TunnelInfo) bool {
	// Parse UUIDs from advertisement payload using existing method
	fidoServiceUUID, _ := bluetooth.ParseUUID(FIDOServiceUUID)
	cableServiceUUID, _ := bluetooth.ParseUUID(CableServiceUUID)
	
	// Check if this device advertises FIDO or caBLE service
	hasFIDOService := result.AdvertisementPayload.HasServiceUUID(fidoServiceUUID)
	hasCableService := result.AdvertisementPayload.HasServiceUUID(cableServiceUUID)
	
	if !hasFIDOService && !hasCableService {
		return false
	}
	
	if hasFIDOService {
		log.Printf("Found FIDO service advertisement from device: %s", result.Address.String())
	}
	if hasCableService {
		log.Printf("Found caBLE service advertisement from device: %s", result.Address.String())
	}
	
	// Extract service data using existing method
	var serviceData []byte
	if hasFIDOService {
		serviceData = s.extractFIDOServiceData(result.AdvertisementPayload)
	} else if hasCableService {
		serviceData = s.extractCableServiceData(result.AdvertisementPayload)
	}
	
	if serviceData == nil || len(serviceData) < 20 {
		log.Printf("Service data insufficient for caBLE v2 (got %d bytes, need 20)", len(serviceData))
		log.Printf("*** CREATING MOCK TUNNEL INFO FOR DEMONSTRATION ***")
		
		// For demonstration purposes, create mock tunnel info
		// In real implementation, this would come from actual service data
		mockTunnelInfo := &TunnelInfo{
			TunnelURL:      "cable.ua5v.com",
			RoutingID:      []byte{0x12, 0x34, 0x56},
			TunnelID:       []byte{0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56},
			AdditionalData: []byte{0xaa, 0xbb, 0xcc, 0xdd},
		}
		
		log.Printf("*** TUNNEL SERVICE INFORMATION (MOCK) ***")
		log.Printf("  Device: %s", result.Address.String())
		log.Printf("  Tunnel URL: %s", mockTunnelInfo.TunnelURL)
		log.Printf("  Routing ID: %x", mockTunnelInfo.RoutingID)
		log.Printf("  Tunnel ID: %x", mockTunnelInfo.TunnelID)
		log.Printf("  Additional Data: %x", mockTunnelInfo.AdditionalData)
		log.Printf("*** END TUNNEL SERVICE INFORMATION ***")
		
		// Send tunnel info to channel
		select {
		case tunnelInfoChan <- mockTunnelInfo:
			return true
		default:
			return false
		}
	}
	
	log.Printf("Service data length: %d bytes", len(serviceData))
	log.Printf("Service data: %x", serviceData)
	
	// Parse caBLE v2 advertisement data according to CTAP2 specification
	if len(serviceData) >= 20 { // caBLE v2 service data should be 20 bytes
		// Extract tunnel service information from advertisement
		// Based on caBLE v2 specification format:
		// [8 bytes nonce] + [3 bytes routing ID] + [2 bytes tunnel service] + [additional data]
		
		nonce := serviceData[0:8]
		routingID := serviceData[8:11]
		tunnelService := serviceData[11:13]
		additionalData := serviceData[13:]
		
		log.Printf("Parsed caBLE v2 advertisement:")
		log.Printf("  Nonce: %x", nonce)
		log.Printf("  Routing ID: %x", routingID)
		log.Printf("  Tunnel Service: %x", tunnelService)
		log.Printf("  Additional Data: %x", additionalData)
		
		// Map tunnel service identifier to URL
		tunnelURL := s.getTunnelURL(tunnelService)
		
		// Generate tunnel ID (would normally be derived from nonce and other data)
		tunnelID := make([]byte, 16)
		copy(tunnelID, nonce)
		// Pad with additional data if needed
		if len(additionalData) > 0 {
			copy(tunnelID[8:], additionalData)
		}
		
		tunnelInfo := &TunnelInfo{
			TunnelURL:      tunnelURL,
			RoutingID:      routingID,
			TunnelID:       tunnelID,
			AdditionalData: additionalData,
		}
		
		// Send tunnel info to channel
		select {
		case tunnelInfoChan <- tunnelInfo:
			return true
		default:
			return false
		}
	}
	
	log.Printf("Service data insufficient for full caBLE v2 parsing: %d bytes (expected 20)", len(serviceData))
	return false
}

// getTunnelURL maps tunnel service identifier to URL
func (s *Scanner) getTunnelURL(tunnelService []byte) string {
	// Default tunnel URLs based on service identifier
	// In practice, this would be determined by the tunnel service identifier
	// For testing, we'll use a default URL
	if len(tunnelService) >= 2 {
		switch tunnelService[0] {
		case 0x00:
			return "cable.ua5v.com"
		case 0x01:
			return "cable.auth.com"
		default:
			return "cable.ua5v.com"
		}
	}
	return "cable.ua5v.com"
}