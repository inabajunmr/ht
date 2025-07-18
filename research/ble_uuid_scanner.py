#!/usr/bin/env python3
"""
BLE UUID Scanner for macOS
全ての BLE デバイスの UUID を検出・表示するツール

Requirements:
    pip install bleak

Usage:
    python ble_uuid_scanner.py
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

class BLEUUIDScanner:
    def __init__(self):
        self.running = False
        self.devices_seen = {}
        self.log_dir = "logs"
        self.create_log_directory()
        
    def create_log_directory(self):
        """ログディレクトリを作成"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
    def is_fido_related(self, uuid: str) -> bool:
        """FIDO関連のUUIDかどうかを判定"""
        fido_uuids = [
            "0000fffd-0000-1000-8000-00805f9b34fb",  # FIDO Service
            "0000fff9-0000-1000-8000-00805f9b34fb",  # caBLE Service
            "0000fffc-0000-1000-8000-00805f9b34fb",  # FIDO Test
            "0000fffe-0000-1000-8000-00805f9b34fb",  # FIDO Alternative
        ]
        
        uuid_lower = uuid.lower()
        for fido_uuid in fido_uuids:
            if uuid_lower == fido_uuid.lower():
                return True
                
        # 部分マッチもチェック
        return any(x in uuid_lower for x in ["fffd", "fff9", "fffc", "fffe"])
    
    def log_device_info(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """デバイス情報をログに記録"""
        address = device.address
        timestamp = datetime.datetime.now().isoformat()
        
        # デバイス別ログファイル
        log_filename = f"{self.log_dir}/device_{address.replace(':', '-')}_{int(datetime.datetime.now().timestamp())}.log"
        
        # 初回のみログファイル作成
        if address not in self.devices_seen:
            self.devices_seen[address] = {
                'first_seen': timestamp,
                'log_file': log_filename,
                'scan_count': 0
            }
            
            with open(log_filename, 'w') as f:
                f.write(f"=== BLE Device Analysis for {address} ===\n")
                f.write(f"First seen: {timestamp}\n")
                f.write("=" * 50 + "\n\n")
        
        self.devices_seen[address]['scan_count'] += 1
        log_file = self.devices_seen[address]['log_file']
        
        # ログファイルに詳細情報を記録
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] SCAN #{self.devices_seen[address]['scan_count']}\n")
            f.write(f"  Address: {address}\n")
            f.write(f"  Name: {device.name or '(No name)'}\n")
            f.write(f"  RSSI: {advertisement_data.rssi} dBm\n")
            
            # Service UUIDs (これが重要!)
            f.write("  Service UUIDs:\n")
            if advertisement_data.service_uuids:
                for i, uuid in enumerate(advertisement_data.service_uuids, 1):
                    fido_marker = " *** FIDO RELATED ***" if self.is_fido_related(uuid) else ""
                    f.write(f"    {i}. {uuid}{fido_marker}\n")
            else:
                f.write("    (No service UUIDs advertised)\n")
            
            # Service Data
            f.write("  Service Data:\n")
            if advertisement_data.service_data:
                for uuid, data in advertisement_data.service_data.items():
                    f.write(f"    {uuid}: {data.hex()}\n")
            else:
                f.write("    (No service data)\n")
            
            # Manufacturer Data
            f.write("  Manufacturer Data:\n")
            if advertisement_data.manufacturer_data:
                for company_id, data in advertisement_data.manufacturer_data.items():
                    f.write(f"    Company {company_id}: {data.hex()}\n")
            else:
                f.write("    (No manufacturer data)\n")
            
            # Local Name
            if advertisement_data.local_name:
                f.write(f"  Local Name: {advertisement_data.local_name}\n")
            
            f.write("\n")
        
        # コンソール出力
        print(f"[{timestamp}] Device: {address}")
        print(f"  Name: {device.name or '(No name)'}")
        print(f"  RSSI: {advertisement_data.rssi} dBm")
        
        if advertisement_data.service_uuids:
            print(f"  Service UUIDs ({len(advertisement_data.service_uuids)}):")
            for uuid in advertisement_data.service_uuids:
                fido_marker = " *** FIDO RELATED ***" if self.is_fido_related(uuid) else ""
                print(f"    - {uuid}{fido_marker}")
                
                if self.is_fido_related(uuid):
                    print(f"\n🎉 *** FIDO/CTAP SERVICE DETECTED ***")
                    print(f"    Device: {address}")
                    print(f"    UUID: {uuid}")
                    print(f"    RSSI: {advertisement_data.rssi} dBm")
                    print(f"    Name: {device.name or '(No name)'}")
                    print(f"*** END FIDO DETECTION ***\n")
        else:
            print("  Service UUIDs: (none)")
        
        print("-" * 60)
    
    def detection_callback(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """BLE デバイス検出時のコールバック"""
        self.log_device_info(device, advertisement_data)
    
    async def start_scanning(self, duration: Optional[int] = None):
        """BLE スキャンを開始"""
        print("🔍 Starting BLE UUID Scanner...")
        print("📱 Scan your QR code with smartphone to start FIDO authentication")
        print("🔎 Looking for FIDO Service UUIDs:")
        print("   - 0000fffd-0000-1000-8000-00805f9b34fb (FIDO)")
        print("   - 0000fff9-0000-1000-8000-00805f9b34fb (caBLE)")
        print("=" * 60)
        
        self.running = True
        
        # スキャナーを作成
        scanner = BleakScanner(detection_callback=self.detection_callback)
        
        try:
            if duration:
                print(f"⏱️  Scanning for {duration} seconds...")
                await scanner.start()
                await asyncio.sleep(duration)
                await scanner.stop()
            else:
                print("⏱️  Scanning indefinitely (Ctrl+C to stop)...")
                await scanner.start()
                # 無限ループ (Ctrl+C で停止)
                while self.running:
                    await asyncio.sleep(1)
                await scanner.stop()
                    
        except KeyboardInterrupt:
            print("\n🛑 Scanning stopped by user")
            await scanner.stop()
        except Exception as e:
            print(f"❌ Error during scanning: {e}")
            await scanner.stop()
        finally:
            self.running = False
            print(f"\n📄 Log files saved in '{self.log_dir}/' directory")
            print(f"📊 Total devices seen: {len(self.devices_seen)}")
    
    def stop(self):
        """スキャンを停止"""
        self.running = False

def signal_handler(signum, frame):
    """シグナルハンドラー"""
    print("\n🛑 Received interrupt signal, stopping scanner...")
    sys.exit(0)

async def main():
    """メイン関数"""
    # シグナルハンドラーを設定
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    scanner = BLEUUIDScanner()
    
    # 引数があれば時間制限付きスキャン
    duration = None
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Usage: python ble_uuid_scanner.py [duration_seconds]")
            return
    
    await scanner.start_scanning(duration)

if __name__ == "__main__":
    asyncio.run(main())