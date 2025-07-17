.PHONY: build test clean run help

# デフォルトターゲット
all: build

# ビルド
build:
	@echo "Building CTAP2 Hybrid Transport..."
	@mkdir -p bin
	@go build -o bin/ctap2-hybrid cmd/ctap2-hybrid/main.go
	@echo "Build completed: bin/ctap2-hybrid"

# テスト実行
test:
	@echo "Running tests..."
	@go test ./... -v

# テストカバレッジ
test-cover:
	@echo "Running tests with coverage..."
	@go test ./... -cover

# 実行
run: build
	@echo "Running CTAP2 Hybrid Transport..."
	@./bin/ctap2-hybrid

# クリーンアップ
clean:
	@echo "Cleaning up..."
	@rm -rf bin/
	@go clean

# 依存関係の取得
deps:
	@echo "Downloading dependencies..."
	@go mod tidy

# フォーマット
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# リント
lint:
	@echo "Running linter..."
	@golint ./...

# ヘルプ
help:
	@echo "Available targets:"
	@echo "  build      - Build the application"
	@echo "  test       - Run tests"
	@echo "  test-cover - Run tests with coverage"
	@echo "  run        - Build and run the application"
	@echo "  clean      - Clean build artifacts"
	@echo "  deps       - Download dependencies"
	@echo "  fmt        - Format code"
	@echo "  lint       - Run linter"
	@echo "  help       - Show this help message"