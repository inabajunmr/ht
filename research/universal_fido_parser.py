#!/usr/bin/env python3
"""
Universal FIDO/caBLE Parser
全てのBLEアドバタイズメントデータをFIDO/caBLE構造として解析

Usage:
    python universal_fido_parser.py [duration]
"""

import asyncio
import datetime
import json
import os
import sys
from typing import Dict, List, Optional, Tuple
import signal
import struct

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("Error: bleak library not found")
    print("Install with: pip install bleak")
    sys.exit(1)

class UniversalFIDOParser:
    def __init__(self):
        self.running = False
        self.scan_count = 0
        self.fido_candidates = []
        
    def analyze_manufacturer_data(self, company_id: int, data: bytes) -> Dict:
        """Manufacturer Dataをあらゆる角度から解析"""
        analysis = {
            'company_id': company_id,
            'raw_data': data.hex(),
            'length': len(data),
            'possible_fido_structures': []
        }
        
        # Apple Manufacturer Data (Company 76)の詳細解析
        if company_id == 76 and len(data) >= 9:
            analysis['apple_specific'] = {
                'type_flag': data[0] if len(data) > 0 else None,
                'subtype': data[1] if len(data) > 1 else None,
                'remaining_data': data[2:].hex() if len(data) > 2 else None
            }
            
            # caBLE v2構造として解析（20バイト期待だが短い場合も考慮）
            if len(data) >= 9:
                # Apple Manufacturer Dataの後半部分をcaBLE候補として扱う
                cable_candidate = data[2:]  # 最初の2バイトを除く
                analysis['possible_fido_structures'].append({
                    'type': 'apple_cable_candidate',
                    'data': cable_candidate.hex(),
                    'analysis': self.analyze_cable_structure(cable_candidate)
                })
        
        # 任意の長さのデータをcaBLE構造として試行
        if len(data) >= 16:  # 最低16バイトあれば解析を試行
            analysis['possible_fido_structures'].append({
                'type': 'generic_cable_candidate',
                'data': data.hex(),
                'analysis': self.analyze_cable_structure(data)
            })
            
        # 20バイト構造の検出
        if len(data) == 20:
            analysis['possible_fido_structures'].append({
                'type': 'exact_cable_v2_length',
                'data': data.hex(),
                'analysis': self.analyze_cable_structure(data),
                'confidence': 'high'
            })
            
        return analysis
    
    def analyze_cable_structure(self, data: bytes) -> Dict:
        """データをcaBLE v2構造として解析"""
        analysis = {
            'length': len(data),
            'cable_v2_analysis': None,
            'patterns': []
        }
        
        if len(data) >= 16:
            # caBLE v2形式として解析
            # [1 byte flags] + [10 bytes nonce] + [3 bytes routing] + [2 bytes tunnel] + [4 bytes hmac]
            if len(data) >= 20:
                flags = data[0]
                nonce = data[1:11]
                routing_id = data[11:14]
                tunnel_service = data[14:16]
                hmac_tag = data[16:20]
                
                analysis['cable_v2_analysis'] = {
                    'flags': f"0x{flags:02x}",
                    'flags_valid': flags == 0x00,  # caBLE v2では通常0
                    'nonce': nonce.hex(),
                    'routing_id': routing_id.hex(),
                    'tunnel_service': tunnel_service.hex(),
                    'tunnel_service_int': struct.unpack('<H', tunnel_service)[0],
                    'hmac_tag': hmac_tag.hex(),
                    'structure_score': self.calculate_structure_score(flags, nonce, routing_id, tunnel_service)
                }
            
            # パターン検出
            analysis['patterns'] = self.detect_patterns(data)
            
        return analysis
    
    def calculate_structure_score(self, flags: int, nonce: bytes, routing_id: bytes, tunnel_service: bytes) -> int:
        """caBLE構造としての妥当性スコア（0-100）"""
        score = 0
        
        # フラグが0（期待値）
        if flags == 0x00:
            score += 30
        elif flags <= 0x0F:  # 小さな値
            score += 10
            
        # ナンスがランダムっぽい（エントロピーチェック）
        unique_bytes = len(set(nonce))
        if unique_bytes >= 8:  # 10バイト中8バイト以上がユニーク
            score += 25
        elif unique_bytes >= 6:
            score += 15
            
        # ルーティングIDがゼロでない
        if any(b != 0 for b in routing_id):
            score += 20
            
        # トンネルサービスID（通常0x0000が多い）
        tunnel_int = struct.unpack('<H', tunnel_service)[0]
        if tunnel_int == 0x0000:
            score += 15
        elif tunnel_int <= 0x00FF:
            score += 10
            
        # 全体がゼロでない
        if any(b != 0 for b in nonce + routing_id + tunnel_service):
            score += 10
            
        return min(score, 100)
    
    def detect_patterns(self, data: bytes) -> List[str]:
        """データのパターンを検出"""
        patterns = []
        
        # 繰り返しパターン
        if len(set(data)) == 1:
            patterns.append(f"all_same_byte_0x{data[0]:02x}")
        
        # 連続パターン
        if data == bytes(range(data[0], data[0] + len(data))):
            patterns.append("sequential_bytes")
            
        # ゼロが多い
        zero_count = data.count(0)
        if zero_count > len(data) // 2:
            patterns.append(f"mostly_zeros_{zero_count}/{len(data)}")
            
        # 高エントロピー（ランダムっぽい）
        unique_count = len(set(data))
        if unique_count > len(data) * 0.8:
            patterns.append("high_entropy")
            
        return patterns
    
    def analyze_service_data(self, service_data: Dict) -> List[Dict]:
        """Service Dataを解析"""
        candidates = []
        
        for uuid_str, data in service_data.items():
            analysis = {
                'uuid': uuid_str,
                'data': data.hex(),
                'length': len(data),
                'fido_analysis': None
            }
            
            # UUIDが16-bit短縮形かチェック
            if len(uuid_str) == 4:  # "fff9" などの短縮形
                full_uuid = f"0000{uuid_str}-0000-1000-8000-00805f9b34fb"
                analysis['full_uuid'] = full_uuid
                
                # FIDO関連UUIDかチェック
                if uuid_str.lower() in ['fffd', 'fff9', 'fffc', 'fffe']:
                    analysis['is_fido_uuid'] = True
                    
            # データをcaBLE構造として解析
            if len(data) >= 16:
                analysis['fido_analysis'] = self.analyze_cable_structure(data)
                
            candidates.append(analysis)
            
        return candidates
    
    def log_comprehensive_analysis(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """包括的なFIDO解析ログ"""
        timestamp = datetime.datetime.now().isoformat()
        self.scan_count += 1
        
        # iPadデバイスまたは高スコアデバイスをハイライト
        is_ipad = "ipad" in (device.name or "").lower()
        
        analysis = {
            'timestamp': timestamp,
            'scan_count': self.scan_count,
            'device': {
                'address': device.address,
                'name': device.name,
                'rssi': advertisement_data.rssi
            },
            'fido_analysis': {
                'service_data_candidates': [],
                'manufacturer_data_candidates': [],
                'total_score': 0,
                'is_fido_candidate': False
            }
        }
        
        # Service Data解析
        if advertisement_data.service_data:
            analysis['fido_analysis']['service_data_candidates'] = self.analyze_service_data(advertisement_data.service_data)
            
        # Manufacturer Data解析
        if advertisement_data.manufacturer_data:
            for company_id, data in advertisement_data.manufacturer_data.items():
                candidate = self.analyze_manufacturer_data(company_id, data)
                analysis['fido_analysis']['manufacturer_data_candidates'].append(candidate)
                
        # 総合スコア計算
        max_score = 0
        for candidate in analysis['fido_analysis']['manufacturer_data_candidates']:
            for structure in candidate.get('possible_fido_structures', []):
                cable_analysis = structure.get('analysis', {}).get('cable_v2_analysis')
                if cable_analysis:
                    score = cable_analysis.get('structure_score', 0)
                    max_score = max(max_score, score)
                    
        analysis['fido_analysis']['total_score'] = max_score
        analysis['fido_analysis']['is_fido_candidate'] = max_score >= 30
        
        # 高スコアまたはiPadの場合は詳細出力
        if max_score >= 20 or is_ipad:
            print(f"\n[{timestamp}] SCAN #{self.scan_count} - FIDO Analysis")
            print(f"  Device: {device.address} ({device.name})")
            print(f"  RSSI: {advertisement_data.rssi} dBm")
            print(f"  FIDO Score: {max_score}/100")
            
            if is_ipad:
                print("  *** iPAD DEVICE DETECTED ***")
                
            # Manufacturer Data詳細
            for candidate in analysis['fido_analysis']['manufacturer_data_candidates']:
                print(f"  Manufacturer Data (Company {candidate['company_id']}):")
                print(f"    Raw: {candidate['raw_data']}")
                
                if candidate['company_id'] == 76:  # Apple
                    apple_data = candidate.get('apple_specific', {})
                    print(f"    Apple Type: 0x{apple_data.get('type_flag', 0):02x}")
                    print(f"    Apple Subtype: 0x{apple_data.get('subtype', 0):02x}")
                    
                for structure in candidate.get('possible_fido_structures', []):
                    print(f"    {structure['type']}:")
                    cable_analysis = structure.get('analysis', {}).get('cable_v2_analysis')
                    if cable_analysis:
                        print(f"      Score: {cable_analysis['structure_score']}/100")
                        print(f"      Flags: {cable_analysis['flags']} (valid: {cable_analysis['flags_valid']})")
                        print(f"      Nonce: {cable_analysis['nonce']}")
                        print(f"      Routing: {cable_analysis['routing_id']}")
                        print(f"      Tunnel: {cable_analysis['tunnel_service']} (int: {cable_analysis['tunnel_service_int']})")
                        print(f"      HMAC: {cable_analysis['hmac_tag']}")
                        
                        if cable_analysis['structure_score'] >= 50:
                            print("      *** HIGH CONFIDENCE FIDO STRUCTURE ***")
                            
            print("  " + "="*60)
            
        # 高スコア候補を記録
        if max_score >= 30:
            self.fido_candidates.append(analysis)
    
    async def scan_universal_fido(self, duration: int = 60):
        """全デバイスを対象にFIDO解析スキャン"""
        print("🔍 Universal FIDO/caBLE Structure Parser")
        print("=" * 70)
        print("🎯 Analyzing ALL BLE advertisements for FIDO/caBLE structures")
        print("📱 Looking for hidden FIDO data in ANY advertisement format")
        print("🍎 Special focus on Apple Manufacturer Data patterns")
        print("=" * 70)
        print(f"⏱️  Scanning for {duration} seconds...")
        
        self.running = True
        
        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            if self.running:
                self.log_comprehensive_analysis(device, advertisement_data)
        
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
        print(f"\n📊 FIDO Analysis Summary:")
        print(f"   Total scans: {self.scan_count}")
        print(f"   FIDO candidates found: {len(self.fido_candidates)}")
        
        if self.fido_candidates:
            print(f"\n🎯 Top FIDO Candidates:")
            sorted_candidates = sorted(self.fido_candidates, 
                                     key=lambda x: x['fido_analysis']['total_score'], 
                                     reverse=True)
            
            for i, candidate in enumerate(sorted_candidates[:5]):
                device = candidate['device']
                score = candidate['fido_analysis']['total_score']
                print(f"   {i+1}. {device['name']} ({device['address']}) - Score: {score}/100")
                
            # ログファイル保存
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = f"logs/universal_fido_analysis_{timestamp}.json"
            with open(log_file, 'w') as f:
                json.dump({
                    'scan_summary': {
                        'total_scans': self.scan_count,
                        'candidates_found': len(self.fido_candidates),
                        'scan_duration': duration
                    },
                    'candidates': sorted_candidates
                }, f, indent=2)
            print(f"   📄 Detailed analysis saved: {log_file}")
        else:
            print("   ❌ No high-confidence FIDO structures detected")
            print("   💡 Try scanning during active WebAuthn QR code scanning")

def signal_handler(signum, frame):
    print("\n🛑 Universal scan interrupted by user")
    sys.exit(0)

async def main():
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Usage: python universal_fido_parser.py [duration_seconds]")
            sys.exit(1)
    else:
        duration = 30  # Default 30 seconds
    
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = UniversalFIDOParser()
    await parser.scan_universal_fido(duration)

if __name__ == "__main__":
    asyncio.run(main())