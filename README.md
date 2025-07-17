# CTAP2 Hybrid Transport

CTAP2 Hybrid Transport の Go 実装です。QRコードの表示、BLEアドバタイズメント、tunnel service経由でのスマートフォンとの通信によりWebAuthnアテステーションを取得します。

## 概要

このプロジェクトは CTAP2.2 仕様に基づいて Hybrid Transport を実装し、以下の機能を提供します：

- QRコード生成・表示
- BLEアドバタイズメント 
- Tunnel service経由での通信
- CTAP2メッセージハンドリング
- アテステーション受信・保存

## 必要要件

- Go 1.19以上
- macOS/Linux (BLE機能のため)
- BLE対応デバイス

## ビルド

```bash
# 依存関係を取得
go mod tidy

# ビルド
go build -o bin/ctap2-hybrid cmd/ctap2-hybrid/main.go

# または make を使用
make build
```

## 実行

```bash
# 基本実行
./bin/ctap2-hybrid

# オプション指定
./bin/ctap2-hybrid -output=my-attestation.json -timeout=10m

# ヘルプ表示
./bin/ctap2-hybrid -help
```

## 使用方法

1. **QRコード表示**: アプリケーションを起動すると、ターミナルにQRコードが表示されます
2. **スマートフォンでスキャン**: 表示されたQRコードをスマートフォンのカメラでスキャンします
3. **BLE接続**: 自動的にBLE接続が確立されます
4. **認証実行**: スマートフォンでWebAuthn認証を実行します
5. **アテステーション保存**: 認証完了後、アテステーションデータがファイルに保存されます

## オプション

- `-output`: アテステーションデータの保存先ファイル名 (default: "attestation.json")
- `-tunnel`: Tunnel serviceのURL (default: "wss://cableconnect.googleapis.com/v1/connect")
- `-timeout`: 操作タイムアウト時間 (default: 5m)

## テスト

```bash
# 全テスト実行
go test ./...

# 特定パッケージのテスト
go test ./pkg/qrcode -v

# カバレッジ付きテスト
go test ./... -cover
```

## プロジェクト構造

```
.
├── cmd/
│   └── ctap2-hybrid/          # メインアプリケーション
├── pkg/
│   ├── qrcode/                # QRコード生成・表示
│   ├── ble/                   # BLEアドバタイズメント
│   ├── tunnel/                # Tunnel service通信
│   ├── ctap2/                 # CTAP2プロトコル処理
│   └── attestation/           # アテステーション保存
├── internal/
│   └── test/                  # テストユーティリティ
├── bin/                       # ビルド成果物
└── README.md
```

## 実装状況

### 完了済み
- [x] QRコード生成・表示機能
- [x] 基本的なプロジェクト構造
- [x] CBOR エンコーディング
- [x] コマンドライン引数処理

### 開発中
- [ ] BLEアドバタイズメント機能
- [ ] Tunnel service通信
- [ ] CTAP2メッセージハンドリング
- [ ] アテステーション受信・保存

### 今後の予定
- [ ] 実際のBLE実装 (tinygo.org/x/bluetooth)
- [ ] WebSocket tunnel実装
- [ ] Noise protocol実装
- [ ] 完全なCTAP2サポート
- [ ] エラーハンドリング改善

## 技術仕様

- **CTAP2.2**: Client to Authenticator Protocol 2.2
- **Hybrid Transport**: QR-initiated transactions
- **暗号化**: Curve25519, Noise Protocol Framework
- **データ形式**: CBOR (Concise Binary Object Representation)
- **通信**: WebSocket, BLE

## 注意事項

- 現在の実装は基本的な機能のみ動作します
- BLE機能は現在スタブ実装です
- 実際のスマートフォン連携にはさらなる実装が必要です
- セキュリティ実装は開発中です

## 貢献

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## ライセンス

MIT License