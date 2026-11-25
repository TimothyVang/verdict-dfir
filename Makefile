.PHONY: build build-core test doctor serve rust-check rust-build

build-core:
	npm run build:core

build:
	npm run build

test:
	npm test

doctor:
	npm run doctor

serve:
	npm run serve

rust-check:
	cargo check --workspace

rust-build:
	cargo build --release -p findevil-mcp
