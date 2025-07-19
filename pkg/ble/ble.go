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
	TunnelURL             string
	ConnectionNonce       []byte  // 10-byte connection nonce (proves proximity)
	RoutingID             []byte  // 3-byte routing ID
	TunnelServiceID       []byte  // 2-byte tunnel service identifier
	EncodedTunnelDomain   uint16  // Tunnel service domain (derived from service ID)
	AdditionalData        []byte  // Additional data (if any)
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
	must("enable BLE stack", adapter.Enable())

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
				log.Printf("Context cancelled, exiting scan loop")
				return
			default:
				log.Println("Starting BLE scan cycle...")
				
				err := s.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
					// Immediate context check at start of callback
					select {
					case <-ctx.Done():
						return
					default:
					}
					deviceAddr := result.Address.String()
					localName := result.AdvertisementPayload.LocalName()
					
					// Log every BLE device found (console output)
					log.Printf("BLE Device: %s (RSSI: %d dBm)", deviceAddr, result.RSSI)
					if localName != "" {
						log.Printf("  Local Name: %s", localName)
					} else {
						log.Printf("  Local Name: (not available)")
					}
					
					// Special logging for iPad device
					if deviceAddr == "394c3434-49ab-2b33-5bb4-228481792d55" || 
					   deviceAddr == "394C3434-49AB-2B33-5BB4-228481792D55" {
						log.Printf("  *** This is the known iPad device ***")
						log.Printf("  *** iPad detected in regular scan - will check for caBLE data ***")
						
						// Force iPad processing
						go func() {
							log.Printf("Processing iPad device for caBLE data...")
							// Try to process as potential tunnel advertisement
							if s.processTunnelAdvertisement(result, make(chan *TunnelInfo, 1)) {
								log.Printf("iPad caBLE processing successful!")
							} else {
								log.Printf("iPad caBLE processing - no caBLE data found (expected)")
							}
						}()
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
						
						// Service data extraction now handled by WaitForTunnelAdvertisement
						if fidoServiceFound {
							log.Printf("FIDO Service UUID found - will extract service data via ServiceData() method")
						}
						
						if cableServiceFound {
							log.Printf("caBLE Service UUID found - will extract service data via ServiceData() method")
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
					// Exit on error or context cancellation
					select {
					case <-ctx.Done():
						return
					default:
					}
				}
				
				// Wait before next scan cycle with context check
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Second):
					// Continue to next iteration
				}
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
	
	// Log service data extraction capability
	logFile.WriteString("  Service Data Extraction:\n")
	logFile.WriteString("    - Service data available via ServiceData() method in TinyGo v0.12.0\n")
	
	logFile.WriteString("\n")
	logFile.Sync() // Ensure data is written immediately
}






// WaitForTunnelAdvertisement waits for a BLE advertisement containing tunnel service information
func (s *Scanner) WaitForTunnelAdvertisement(ctx context.Context) (*TunnelInfo, error) {
	log.Printf("Waiting for BLE advertisement with tunnel service information...")
	
	// Channel to receive tunnel information
	tunnelInfoChan := make(chan *TunnelInfo, 1)
	scanErrChan := make(chan error, 1)
	scanDoneChan := make(chan bool, 1)
	
	// Start scanning with context timeout
	go func() {
		defer func() {
			log.Printf("Stopping BLE scan...")
			if err := s.adapter.StopScan(); err != nil {
				log.Printf("Error stopping scan: %v", err)
			}
			scanDoneChan <- true
		}()
		
		// Monitor context cancellation in a separate goroutine
		go func() {
			<-ctx.Done()
			log.Printf("Context cancelled, forcing scan stop")
			s.adapter.StopScan()
		}()
		
		err := s.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
			// Check if context is cancelled immediately
			select {
			case <-ctx.Done():
				log.Printf("Context cancelled in scan callback")
				return
			default:
			}
			
			deviceID := result.Address.String()
			rssi := result.RSSI
			localName := result.AdvertisementPayload.LocalName()
			
			// Log device discovery
			log.Printf("BLE Device found: %s (RSSI: %d dBm)", deviceID, rssi)
			if localName != "" {
				log.Printf("  Name: %s", localName)
			}
			
			// Check for iPad device
			isIPad := strings.Contains(strings.ToLower(localName), "ipad") || 
				deviceID == "394c3434-49ab-2b33-5bb4-228481792d55" || 
				deviceID == "394C3434-49AB-2B33-5BB4-228481792D55"
				
			if isIPad {
				log.Printf("*** DETECTED iPAD DEVICE IN TUNNEL SCAN: %s ***", deviceID)
				log.Printf("  Will attempt iPad-specific caBLE extraction")
			}
			
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
			select {
			case scanErrChan <- err:
			case <-ctx.Done():
			}
		}
	}()
	
	// Wait for tunnel info, scan error, or context cancellation
	select {
	case tunnelInfo := <-tunnelInfoChan:
		log.Printf("Successfully received tunnel info, stopping scan...")
		return tunnelInfo, nil
	case err := <-scanErrChan:
		log.Printf("Scan error occurred, stopping scan...")
		return nil, fmt.Errorf("failed to start BLE scan: %w", err)
	case <-ctx.Done():
		log.Printf("Context timeout/cancellation, waiting for scan to stop...")
		// Wait for scan to actually stop
		select {
		case <-scanDoneChan:
			log.Printf("Scan stopped gracefully")
		case <-time.After(2 * time.Second):
			log.Printf("Scan stop timeout, forcing exit")
		}
		return nil, ctx.Err()
	}
}

// processTunnelAdvertisement processes BLE advertisement data for tunnel service information
func (s *Scanner) processTunnelAdvertisement(result bluetooth.ScanResult, tunnelInfoChan chan *TunnelInfo) bool {
	deviceAddr := result.Address.String()
	localName := result.AdvertisementPayload.LocalName()
	
	// Parse UUIDs from advertisement payload using existing method
	fidoServiceUUID, _ := bluetooth.ParseUUID(FIDOServiceUUID)
	cableServiceUUID, _ := bluetooth.ParseUUID(CableServiceUUID)
	
	// Check if this device advertises FIDO or caBLE service
	hasFIDOService := result.AdvertisementPayload.HasServiceUUID(fidoServiceUUID)
	hasCableService := result.AdvertisementPayload.HasServiceUUID(cableServiceUUID)
	
	// Special handling for iPad devices - check Apple Manufacturer Data
	// iPad detection: either by name or known device ID
	isIPad := strings.Contains(strings.ToLower(localName), "ipad") || 
		deviceAddr == "394c3434-49ab-2b33-5bb4-228481792d55" || 
		deviceAddr == "394C3434-49AB-2B33-5BB4-228481792D55"
	
	var appleManufacturerData []byte
	
	if isIPad {
		log.Printf("*** DETECTED iPAD DEVICE: %s ***", deviceAddr)
		log.Printf("  Detection method: %s", func() string {
			if strings.Contains(strings.ToLower(localName), "ipad") {
				return "Local Name"
			}
			return "Known Device ID"
		}())
		
		// TODO: Extract manufacturer data when TinyGo Bluetooth supports it
		// For now, we'll check service UUIDs as fallback
		log.Printf("  Device Name: %s", localName)
		log.Printf("  Note: iPad devices embed caBLE info in Apple Manufacturer Data (Company ID 76)")
		log.Printf("  Checking for standard service UUIDs as fallback...")
		
		// Check if there's any potential caBLE data in manufacturer data
		// This would need TinyGo Bluetooth manufacturer data support
		appleManufacturerData = s.extractAppleManufacturerData(result)
		if len(appleManufacturerData) > 0 {
			log.Printf("  Found Apple Manufacturer Data: %x", appleManufacturerData)
			if s.tryAppleManufacturerDataDecryption(appleManufacturerData, tunnelInfoChan) {
				return true
			}
		}
	}
	
	if !hasFIDOService && !hasCableService && !isIPad {
		return false
	}
	
	if hasFIDOService {
		log.Printf("Found FIDO service advertisement from device: %s", result.Address.String())
	}
	if hasCableService {
		log.Printf("Found caBLE service advertisement from device: %s", result.Address.String())
	}
	
	// Extract service data directly using TinyGo Bluetooth v0.12.0 ServiceData() method
	var serviceData []byte
	
	// Get service data entries
	serviceDataEntries := result.AdvertisementPayload.ServiceData()
	if len(serviceDataEntries) > 0 {
		// Parse target UUIDs
		cableServiceUUID, _ := bluetooth.ParseUUID(CableServiceUUID)
		fidoServiceUUID, _ := bluetooth.ParseUUID(FIDOServiceUUID)
		
		// Find caBLE or FIDO service data
		for _, entry := range serviceDataEntries {
			if entry.UUID == cableServiceUUID {
				log.Printf("Found caBLE service data (UUID 0xFFF9): %x (length: %d)", entry.Data, len(entry.Data))
				serviceData = entry.Data
				break
			} else if entry.UUID == fidoServiceUUID {
				log.Printf("Found FIDO service data (UUID 0xFFFD): %x (length: %d)", entry.Data, len(entry.Data))
				serviceData = entry.Data
				break
			}
		}
	}
	
	// For standard devices (non-iPad), require service data
	if !isIPad && (serviceData == nil || len(serviceData) < 20) {
		log.Printf("Service data insufficient for caBLE v2 (got %d bytes, need 20)", len(serviceData))
		return false
	}
	
	// For iPad devices, we've already tried Apple Manufacturer Data above
	// If we reach here with an iPad but no service data, that's expected
	if isIPad && (serviceData == nil || len(serviceData) < 20) {
		log.Printf("iPad device detected without standard service data - this is expected")
		log.Printf("iPad uses Apple Manufacturer Data embedding (already attempted above)")
		return false
	}
	
	log.Printf("Service data length: %d bytes", len(serviceData))
	log.Printf("Service data (encrypted): %x", serviceData)
	
	// Try to decrypt and process the service data
	return s.tryDecryptCableData(serviceData, tunnelInfoChan, "Standard Service Data")
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

// extractAppleManufacturerData attempts to extract Apple manufacturer data from BLE advertisement
func (s *Scanner) extractAppleManufacturerData(result bluetooth.ScanResult) []byte {
	// TODO: This requires TinyGo Bluetooth library support for manufacturer data
	// The current TinyGo Bluetooth library (v0.12.0) has limited manufacturer data access
	// We would need to use the raw advertisement data parsing or wait for library updates
	
	// For now, return empty slice as placeholder
	// In a real implementation, we would parse the raw advertisement payload
	// to extract manufacturer data with Company ID 76 (Apple)
	
	log.Printf("  Warning: TinyGo Bluetooth manufacturer data extraction not yet implemented")
	log.Printf("  Need to parse raw advertisement payload for Company ID 76 (Apple)")
	
	return []byte{}
}

// tryAppleManufacturerDataDecryption attempts to decrypt caBLE data from Apple manufacturer data
func (s *Scanner) tryAppleManufacturerDataDecryption(manufacturerData []byte, tunnelInfoChan chan *TunnelInfo) bool {
	log.Printf("Attempting to decrypt Apple Manufacturer Data as caBLE v2...")
	
	// Apple Manufacturer Data format for caBLE (based on research):
	// [2 bytes: Apple Company ID 0x004C] + [variable: Apple-specific data]
	// The caBLE data is embedded within the Apple-specific portion
	
	if len(manufacturerData) < 9 {
		log.Printf("  Apple Manufacturer Data too short: %d bytes (minimum 9 for caBLE)", len(manufacturerData))
		return false
	}
	
	// Skip first 2 bytes (likely Apple type/subtype flags)
	// Based on research logs, the pattern is: 10054b18c52d68 or 10054718c52d68
	// Where the changing part (4b->47) might contain caBLE information
	cableCandidate := manufacturerData[2:] // Skip type flags
	
	log.Printf("  Apple caBLE candidate data: %x", cableCandidate)
	
	// Try to decrypt as caBLE v2 if we have enough data
	if len(cableCandidate) >= 20 {
		return s.tryDecryptCableData(cableCandidate, tunnelInfoChan, "Apple Manufacturer Data")
	}
	
	// For shorter Apple data, try different extraction strategies
	if len(cableCandidate) >= 7 {
		log.Printf("  Attempting iPad-specific caBLE extraction from %d bytes", len(cableCandidate))
		
		// Extract what we can and pad/extend as needed for testing
		// This is experimental - real iPad implementation may vary
		
		// Try to extract nonce-like data from changing portion
		var paddedData [20]byte
		copy(paddedData[:], cableCandidate)
		
		// Fill remaining with pattern or zeros
		for i := len(cableCandidate); i < 20; i++ {
			paddedData[i] = 0x00
		}
		
		log.Printf("  Padded candidate data: %x", paddedData[:])
		return s.tryDecryptCableData(paddedData[:], tunnelInfoChan, "iPad Apple Data (padded)")
	}
	
	log.Printf("  Apple Manufacturer Data insufficient for caBLE extraction")
	return false
}

// tryDecryptCableData attempts to decrypt caBLE v2 data from any source
func (s *Scanner) tryDecryptCableData(data []byte, tunnelInfoChan chan *TunnelInfo, source string) bool {
	log.Printf("Attempting caBLE v2 decryption from %s...", source)
	
	// Decrypt caBLE v2 data using QR secret
	decryptor := NewCableV2Decryptor(s.qrSecret)
	decryptedData, err := decryptor.DecryptServiceData(data)
	
	var nonce, routingID, tunnelService, additionalData []byte
	var tunnelURL string
	
	if err != nil {
		log.Printf("Failed to decrypt %s as caBLE v2: %v", source, err)
		
		// For iPad, we might need different extraction strategy
		if strings.Contains(source, "iPad") || strings.Contains(source, "Apple") {
			log.Printf("  iPad decryption failed - this is expected as iPad uses different embedding")
			log.Printf("  The changing bytes in Apple data might indicate caBLE activity")
			log.Printf("  Need to research iPad-specific caBLE data format")
		}
		return false
	}
	
	log.Printf("Successfully decrypted %s: %x", source, decryptedData)
	
	// Parse decrypted data according to caBLE v2 specification
	var parseErr error
	nonce, routingID, tunnelService, additionalData, parseErr = ParseDecryptedServiceData(decryptedData)
	if parseErr != nil {
		log.Printf("Failed to parse decrypted data from %s: %v", source, parseErr)
		return false
	}
	
	log.Printf("Decrypted caBLE v2 from %s:", source)
	log.Printf("  Nonce: %x", nonce)
	log.Printf("  Routing ID: %x", routingID)
	log.Printf("  Tunnel Service: %x", tunnelService)
	log.Printf("  Additional Data: %x", additionalData)
	
	// Map tunnel service identifier to URL
	tunnelURL = s.getTunnelURL(tunnelService)
	
	// Extract tunnel service domain from 2-byte identifier
	var encodedTunnelDomain uint16
	if len(tunnelService) >= 2 {
		encodedTunnelDomain = uint16(tunnelService[0]) | (uint16(tunnelService[1]) << 8)
	}
	
	tunnelInfo := &TunnelInfo{
		TunnelURL:           tunnelURL,
		ConnectionNonce:     nonce,
		RoutingID:           routingID,
		TunnelServiceID:     tunnelService,
		EncodedTunnelDomain: encodedTunnelDomain,
		AdditionalData:      additionalData,
	}
	
	// Send tunnel info to channel
	select {
	case tunnelInfoChan <- tunnelInfo:
		log.Printf("Successfully extracted tunnel info from %s", source)
		return true
	default:
		return false
	}
}

// Helper function from TinyGo Bluetooth examples
func must(action string, err error) {
	if err != nil {
		panic("failed to " + action + ": " + err.Error())
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}