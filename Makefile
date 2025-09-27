build-test: test
	@echo "Building application..."
	cargo build

build-release: test
	@echo "Building application..."
	cargo build --release

build-run:
	@echo "Build and Run the Application..."
	cargo build
	RUST_LOG=trace LD_LIBRARY_PATH=~/Development/req-processor/target/release ./target/debug/merino --auth-type smart-auth
	# or it could be: ./target/debug/merino --auth-type smart-auth

run-test:
	RUST_LOG=trace LD_LIBRARY_PATH=~/Development/req-processor/target/release ./target/debug/merino --auth-type smart-auth

RANDOM := $(shell head /dev/urandom | tr -dc A-F0-9 | head -c 8)
TEMP_PATH := /tmp/zirab-$(RANDOM)


test:
	@echo "Starting testing..."
	
grpc:
	@echo "Getting latest version of the proto files and generating gRPC code..."
	@read -p "Do you want to generate gRPC code? (Y/n) " response; \
	if [ "$$response" != "Y" ] && [ "$$response" != "y" ]; then \
		echo "Skipping gRPC code generation."; \
		exit 0; \
	else \
	echo "Fetching gRPC proto..."; \
	read -p "Enter a personal access token with read-permission to the net-sentinel repo: " token; \
	curl -L --header "PRIVATE-TOKEN: $$token" \
		-o "proto/api/net_sentinel.proto" \
		"https://hamgit.ir/api/v4/projects/zirabro%2Fnet-sentinel/repository/files/pkg%2Fgrpc%2Fproto%2Fnet_sentinel%2Fnet_sentinel.proto/raw?ref=main"; \
	echo "Done Successfully 🤗\n(Yo could run \"cargo check\")"; \
	fi

.PHONY: build test grpc

