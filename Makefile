run-debug:
	RUST_LOG=debug cargo run manifest.yaml

run-release:
	RUST_LOG=debug cargo run --release manifest.yaml

build-debug:
	cargo build

build-release:
	cargo build --release