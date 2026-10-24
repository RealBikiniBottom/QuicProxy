test_http3:
	IP=$$(dig +short cloudflare.com | head -1); \
	/opt/homebrew/opt/curl/bin/curl \
		--http3-only \
		--connect-timeout 5 \
		--resolve cloudflare.com:443:$$IP \
		-o /dev/null \
		-s \
		-w 'cloudflare: tls=%{time_appconnect}s total=%{time_total}s\n' \
		https://cloudflare.com

	IP=$$(dig +short quic.nginx.org | head -1); \
	/opt/homebrew/opt/curl/bin/curl \
		--http3-only \
		--connect-timeout 5 \
		--resolve quic.nginx.org:443:$$IP \
		-o /dev/null \
		-s \
		-w 'nginx: tls=%{time_appconnect}s total=%{time_total}s\n' \
		https://quic.nginx.org

run_test_config: build
	./target/release/quicproxy --elevate -c ./tests/test_http3.json5

test:
	cargo test

check:
	cargo check --features "premium"

run_server: build
	./target/release/quicproxy -c ./assets/example_config/server.json5

run_client: build
	./target/release/quicproxy --elevate -c ./src/premium/test/client.json5

run_web_manager: build
	./target/release/quicproxy --manage --port 8081 --web-dir ./src/premium/quicproxy_flutter/build/web

# USE_MIMALLOC=1 时给 build / build-xcframework / build-android 加上 mimalloc feature
USE_MIMALLOC ?= 0
MIMALLOC_FEATURE := $(if $(filter 1,$(USE_MIMALLOC)),mimalloc,)
# mimalloc 把空闲内存还给系统前等待的毫秒数（mimalloc v3 默认 1000；0 立即归还，-1 不归还）。
# 编译期写进二进制，仅 USE_MIMALLOC=1 时生效；运行时设置了同名环境变量则以环境变量为准。
MIMALLOC_PURGE_DELAY ?=
ifneq ($(strip $(MIMALLOC_PURGE_DELAY)),)
export MIMALLOC_PURGE_DELAY
endif

CARGO_FLAGS = --release $(if $(MIMALLOC_FEATURE),--features $(MIMALLOC_FEATURE),)

build:
	cargo build $(CARGO_FLAGS)

debug_build:
	cargo build

build-linux-cross:
	DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --release --target x86_64-unknown-linux-musl --features mimalloc

build-linux-aarch64-cross:
	DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --release --target aarch64-unknown-linux-musl --features mimalloc

build-linux-armv7-cross:
	DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --release --target armv7-unknown-linux-musleabihf --features mimalloc

build-windows-cross:
	DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --release --target x86_64-pc-windows-gnu --features mimalloc

deploy: build-linux-all
	bash ./src/premium/test/deploy_test.sh

clean:
	cargo clean

build-android:
	# cargo install cargo-ndk
	rustup target add aarch64-linux-android armv7-linux-androideabi
	cargo ndk -t arm64-v8a -t armeabi-v7a -o ./src/premium/quicproxy_flutter/android/app/src/main/jniLibs build --release --features "jni,premium $(MIMALLOC_FEATURE)" --lib

# ── Flutter Android 打包（需先执行 build-android 准备好 Rust core） ──
FLUTTER_DIR = ./src/premium/quicproxy_flutter
APK_OUTPUT  = $(FLUTTER_DIR)/build/app/outputs/flutter-apk/app-release.apk

flutter-apk:
	@echo "=== Building Flutter APK (signed) ==="
	cd $(FLUTTER_DIR) && flutter pub get
	cd $(FLUTTER_DIR) && flutter build apk --release
	@echo ""
	@echo "✓ APK: $(APK_OUTPUT)"
	@ls -lh $(APK_OUTPUT)

# 一键打包：Rust core + Flutter APK（自动签名）
android-release: build-android flutter-apk
	@echo ""
	@echo "=== android-release done ==="
	@echo "APK: $(APK_OUTPUT)"
	@ls -lh $(APK_OUTPUT)

# 验证 APK 签名
apk-verify:
	@echo "=== Verifying APK signature ==="
	@if [ ! -f "$(APK_OUTPUT)" ]; then \
		echo "❌ APK not found. Run 'make android-release' first."; \
		exit 1; \
	fi
	jarsigner -verify -verbose -certs $(APK_OUTPUT) 2>&1 | grep -E "jar verified|CN=|Warning" || true
	@echo ""
	@echo "--- Certificate details ---"
	keytool -printcert -jarfile $(APK_OUTPUT) 2>/dev/null || echo "keytool not available"

# CARGO_UPDATE=1 时先 cargo update（会把 quinn-jls 等 git 依赖拉到最新，可能带来不兼容的 API 变化）
CARGO_UPDATE ?= 0

build-xcframework:
	$(if $(filter 1,$(CARGO_UPDATE)),cargo update,@true)
	rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
	@# iOS device
	IPHONEOS_DEPLOYMENT_TARGET=14.0 \
	cargo build --release --target aarch64-apple-ios --features "premium $(MIMALLOC_FEATURE)" --lib
	@# iOS simulator
	IPHONEOS_DEPLOYMENT_TARGET=14.0 \
	cargo build --release --target aarch64-apple-ios-sim --features "premium $(MIMALLOC_FEATURE)" --lib
	IPHONEOS_DEPLOYMENT_TARGET=14.0 \
	cargo build --release --target x86_64-apple-ios --features "premium $(MIMALLOC_FEATURE)" --lib
	@# macOS
	MACOSX_DEPLOYMENT_TARGET=11.0 \
	cargo build --release --target aarch64-apple-darwin --features "apple-network-extension $(MIMALLOC_FEATURE)" --lib
	MACOSX_DEPLOYMENT_TARGET=11.0 \
	cargo build --release --target x86_64-apple-darwin --features "apple-network-extension $(MIMALLOC_FEATURE)" --lib
	@# Merge iOS simulator fat binary
	mkdir -p target/ios-simulator-fat
	lipo -create \
		target/aarch64-apple-ios-sim/release/libquicproxy.a \
		target/x86_64-apple-ios/release/libquicproxy.a \
		-output target/ios-simulator-fat/libquicproxy.a
	@# Merge macOS universal binary
	mkdir -p target/macos-universal
	lipo -create \
		target/aarch64-apple-darwin/release/libquicproxy.a \
		target/x86_64-apple-darwin/release/libquicproxy.a \
		-output target/macos-universal/libquicproxy.a
	@# Unified xcframework (iOS + macOS)
	rm -rf src/premium/quicproxy_flutter/apple/PacketTunnelShared/QuicProxyCore.xcframework
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libquicproxy.a \
		-library target/ios-simulator-fat/libquicproxy.a \
		-library target/macos-universal/libquicproxy.a \
		-output src/premium/quicproxy_flutter/apple/PacketTunnelShared/QuicProxyCore.xcframework

CODE_MMDB_URL ?= https://github.com/JimmyHuang454/Geoip-For-CN/releases/latest/download/Country.mmdb
CODE_MMDB_PATH ?= assets/code.mmdb

.PHONY: update_code_mmdb
update_code_mmdb:
	curl --fail --location --output "$(CODE_MMDB_PATH)" "$(CODE_MMDB_URL)"
