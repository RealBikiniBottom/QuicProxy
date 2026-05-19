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
	cargo test --test socks5_udp_test

check:
	cargo check --features "premium"

run_server: build
	./target/release/quicproxy -c ./assets/example_config/server.json5

run_client: build
	./target/release/quicproxy --elevate -c ./src/premium/test/client.json5

USE_MIMALLOC ?= 0
USE_SNMALLOC ?= 0
CARGO_FLAGS = --release

ifeq ($(USE_MIMALLOC), 1)
	CARGO_FLAGS += --features mimalloc
else ifeq ($(USE_SNMALLOC), 1)
	CARGO_FLAGS += --features snmalloc
endif

build:
	cargo build $(CARGO_FLAGS)

debug_build:
	cargo build

build-linux-cross:
	cross build --release --target x86_64-unknown-linux-musl

build-windows-cross:
	cross build --release --target x86_64-pc-windows-gnu

deploy: build-linux-cross
	bash ./src/premium/test/deploy_test.sh

clean:
	cargo clean

build-android:
	# cargo install cargo-ndk
	rustup target add aarch64-linux-android armv7-linux-androideabi
	cargo ndk -t arm64-v8a -t armeabi-v7a -o ./quicproxy_flutter/android/app/src/main/jniLibs build --release --features "jni,premium"
