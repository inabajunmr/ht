# BLE UUID Research Tools

macOS で BLE デバイスの全ての UUID を検出・分析するためのツール集

## 📋 概要

このディレクトリには、TinyGo Bluetooth の制約を回避して、実際に周辺デバイスがアドバタイズしている全ての Service UUID を確認するためのツールが含まれています。

## 🛠️ ツール

### 1. `ble_uuid_scanner.py`

Python + `bleak` を使用した BLE UUID スキャナー

**機能:**
- ✅ 全ての Service UUID を表示
- ✅ Service Data の詳細解析
- ✅ Manufacturer Data の取得
- ✅ FIDO 関連 UUID の自動検出
- ✅ デバイス別ログファイル出力
- ✅ リアルタイム検出表示

## 🚀 セットアップ

### 1. Python 依存関係のインストール

```bash
pip install bleak
```

### 2. 実行権限の設定

```bash
chmod +x ble_uuid_scanner.py
```

## 💻 使用方法

### 基本実行 (無制限スキャン)

```bash
cd research
python ble_uuid_scanner.py
```

### 時間制限付きスキャン

```bash
# 30秒間スキャン
python ble_uuid_scanner.py 30

# 60秒間スキャン
python ble_uuid_scanner.py 60
```

### 停止方法

```bash
Ctrl+C
```

## 📊 出力例

### コンソール出力

```
🔍 Starting BLE UUID Scanner...
📱 Scan your QR code with smartphone to start FIDO authentication
🔎 Looking for FIDO Service UUIDs:
   - 0000fffd-0000-1000-8000-00805f9b34fb (FIDO)
   - 0000fff9-0000-1000-8000-00805f9b34fb (caBLE)
============================================================

[2025-07-18T15:30:00] Device: AA:BB:CC:DD:EE:FF
  Name: iPhone
  RSSI: -45 dBm
  Service UUIDs (3):
    - 0000180f-0000-1000-8000-00805f9b34fb
    - 0000fffd-0000-1000-8000-00805f9b34fb *** FIDO RELATED ***
    - d0611e78-bbb4-4591-a5f8-487910ae4366

🎉 *** FIDO/CTAP SERVICE DETECTED ***
    Device: AA:BB:CC:DD:EE:FF
    UUID: 0000fffd-0000-1000-8000-00805f9b34fb
    RSSI: -45 dBm
    Name: iPhone
*** END FIDO DETECTION ***
```

### ログファイル出力

```
=== BLE Device Analysis for AA:BB:CC:DD:EE:FF ===
First seen: 2025-07-18T15:30:00
==================================================

[2025-07-18T15:30:00] SCAN #1
  Address: AA:BB:CC:DD:EE:FF
  Name: iPhone
  RSSI: -45 dBm
  Service UUIDs:
    1. 0000180f-0000-1000-8000-00805f9b34fb
    2. 0000fffd-0000-1000-8000-00805f9b34fb *** FIDO RELATED ***
    3. d0611e78-bbb4-4591-a5f8-487910ae4366
  Service Data:
    0000fffd-0000-1000-8000-00805f9b34fb: fd03008142
  Manufacturer Data:
    76: 001122334455
  Local Name: iPhone
```

## 🎯 検証手順

### 1. 基本動作確認

```bash
python ble_uuid_scanner.py 10
```

### 2. スマートフォンでの FIDO テスト

1. スキャナーを起動
```bash
python ble_uuid_scanner.py
```

2. メインの Go プログラムで QR コード表示
```bash
cd ..
go run ./cmd/ctap2-hybrid
```

3. スマートフォンで QR コードをスキャン

4. Python スキャナーの出力で FIDO UUID を確認

### 3. 期待される結果

スマートフォンが FIDO 認証を開始すると以下が表示されるはず:

```
🎉 *** FIDO/CTAP SERVICE DETECTED ***
    Device: [スマートフォンのアドレス]
    UUID: 0000fffd-0000-1000-8000-00805f9b34fb
    RSSI: [信号強度]
    Name: [デバイス名]
*** END FIDO DETECTION ***
```

## 🔍 トラブルシューティング

### `bleak` インストールエラー

```bash
# macOS の場合
pip3 install bleak

# 仮想環境を使用
python -m venv venv
source venv/bin/activate
pip install bleak
```

### 権限エラー

macOS でコアBluetooth API を使用するため、Bluetooth 権限が必要な場合があります。

### 検出されない場合

1. Bluetooth がオンになっているか確認
2. 他の BLE アプリケーションが使用していないか確認
3. スマートフォンの BLE が有効になっているか確認

## 📝 ログファイル

ログファイルは `logs/` ディレクトリに保存されます:

```
logs/
├── device_AA-BB-CC-DD-EE-FF_1752820000.log
├── device_11-22-33-44-55-66_1752820001.log
└── ...
```

各デバイスの完全な通信履歴が記録されます。

## 🔧 カスタマイズ

`ble_uuid_scanner.py` の `is_fido_related()` 関数を編集することで、検出対象の UUID を変更できます。