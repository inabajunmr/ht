#!/usr/bin/env python3
"""
iPad caBLE Hybrid Transport BLE スキャナー
iPadがWebAuthn QRコードをスキャンした時のBLEアドバタイズメントを詳細監視

Usage:
    python detailed_ipad_scanner.py
"""

import asyncio
import datetime
import json
import os
import sys
from typing import Dict, List, Optional
import signal

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("Error: bleak library not found")
    print("Install with: pip install bleak")
    sys.exit(1)

class DetailedIPadScanner:
    def __init__(self):
        self.running = False
        self.ipad_device_id = "394C3434-49AB-2B33-5BB4-228481792D55"
        self.scan_count = 0
        self.ipad_advertisements = []
        
    def log_advertisement(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """アドバタイズメントデータを詳細ログ"""
        timestamp = datetime.datetime.now().isoformat()
        self.scan_count += 1
        
        # iPadデバイスのみに焦点を当てる
        if device.address.upper() == self.ipad_device_id.upper():
            print(f"\n[{timestamp}] SCAN #{self.scan_count} - iPad Advertisement")
            print(f"  Address: {device.address}")
            print(f"  Name: {device.name}")
            print(f"  RSSI: {advertisement_data.rssi} dBm")
            
            # Service UUIDs
            if advertisement_data.service_uuids:
                print(f"  Service UUIDs ({len(advertisement_data.service_uuids)}):")
                for uuid in advertisement_data.service_uuids:
                    print(f"    - {uuid}")
                    # FIDO関連UUIDをハイライト
                    if any(fido in uuid.lower() for fido in ['fffd', 'fff9', 'fffc', 'fffe']):
                        print(f"      *** FIDO-RELATED UUID DETECTED! ***")
            else:
                print("  Service UUIDs: (none)")
            
            # Service Data
            if advertisement_data.service_data:
                print(f"  Service Data ({len(advertisement_data.service_data)} entries):")
                for uuid, data in advertisement_data.service_data.items():
                    print(f"    UUID {uuid}: {data.hex()}")
                    # FIDO関連Service Dataをハイライト
                    if any(fido in uuid.lower() for fido in ['fffd', 'fff9', 'fffc', 'fffe']):
                        print(f"      *** FIDO SERVICE DATA DETECTED! ***")
                        print(f"      Length: {len(data)} bytes")
                        if len(data) == 20:
                            print(f"      *** caBLE v2 LENGTH (20 bytes) ***")
            else:
                print("  Service Data: (none)")
            
            # Manufacturer Data
            if advertisement_data.manufacturer_data:
                print(f"  Manufacturer Data ({len(advertisement_data.manufacturer_data)} entries):")
                for company_id, data in advertisement_data.manufacturer_data.items():
                    print(f"    Company {company_id}: {data.hex()}")
                    if company_id == 76:  # Apple
                        print(f"      (Apple Manufacturer Data)")
            else:
                print("  Manufacturer Data: (none)")
            
            # Local Name
            if advertisement_data.local_name:
                print(f"  Local Name: {advertisement_data.local_name}")
                
            # Platform Data (if available)
            if hasattr(advertisement_data, 'platform_data'):
                print(f"  Platform Data: {advertisement_data.platform_data}")
            
            print("  " + "="*50)
            
            # 記録保存
            record = {
                'timestamp': timestamp,
                'scan_count': self.scan_count,
                'address': device.address,
                'name': device.name,
                'rssi': advertisement_data.rssi,
                'service_uuids': list(advertisement_data.service_uuids) if advertisement_data.service_uuids else [],
                'service_data': {str(k): v.hex() for k, v in advertisement_data.service_data.items()} if advertisement_data.service_data else {},
                'manufacturer_data': {str(k): v.hex() for k, v in advertisement_data.manufacturer_data.items()} if advertisement_data.manufacturer_data else {},
                'local_name': advertisement_data.local_name
            }
            self.ipad_advertisements.append(record)
    
    async def scan_for_ipad(self, duration: int = 60):
        """iPadのBLEアドバタイズメントを監視"""
        print("🔍 iPad caBLE Hybrid Transport BLE Scanner")
        print("=" * 60)
        print(f"📱 Target iPad: {self.ipad_device_id}")
        print("🎯 Instructions:")
        print("   1. Open Chrome on your computer")
        print("   2. Go to a WebAuthn test site (e.g., webauthn.io)")
        print("   3. Click 'Authenticate with Cross-Platform Device'")
        print("   4. Scan the QR code with your iPad")
        print("   5. Watch for FIDO-related BLE advertisements")
        print("=" * 60)
        print(f"⏱️  Monitoring for {duration} seconds...")
        
        self.running = True
        
        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            if self.running:
                self.log_advertisement(device, advertisement_data)
        
        scanner = BleakScanner(detection_callback=detection_callback)
        
        try:
            await scanner.start()
            await asyncio.sleep(duration)
            await scanner.stop()
        except Exception as e:
            print(f"❌ Scanner error: {e}")
        finally:
            self.running = False
            
        # 結果サマリー
        print(f"\n📊 Scan Summary:")
        print(f"   Total iPad advertisements: {len(self.ipad_advertisements)}")
        
        # FIDO関連データを見つけたかチェック
        fido_found = False
        for record in self.ipad_advertisements:
            if record['service_uuids'] or record['service_data']:
                for uuid in record['service_uuids'] + list(record['service_data'].keys()):
                    if any(fido in uuid.lower() for fido in ['fffd', 'fff9', 'fffc', 'fffe']):
                        fido_found = True
                        break
        
        if fido_found:
            print("   ✅ FIDO-related data detected!")
        else:
            print("   ❌ No FIDO-related data detected")
            print("   💡 Possible reasons:")
            print("      - iPad not in FIDO mode")
            print("      - Different Service UUID used")
            print("      - Timing issue (scan after QR code)")
            print("      - iPad uses different transport method")
        
        # ログファイル保存
        if self.ipad_advertisements:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = f"logs/ipad_detailed_scan_{timestamp}.json"
            with open(log_file, 'w') as f:
                json.dump(self.ipad_advertisements, f, indent=2)
            print(f"   📄 Detailed log saved: {log_file}")

def signal_handler(signum, frame):
    print("\n🛑 Scan interrupted by user")
    sys.exit(0)

async def main():
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Usage: python detailed_ipad_scanner.py [duration_seconds]")
            sys.exit(1)
    else:
        duration = 60  # Default 60 seconds
    
    signal.signal(signal.SIGINT, signal_handler)
    
    scanner = DetailedIPadScanner()
    await scanner.scan_for_ipad(duration)

if __name__ == "__main__":
    asyncio.run(main())