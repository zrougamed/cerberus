CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

BINARY := cerberus
BPF_OBJ := build/cerberus_tc.o
BPF_SRC := ebpf/cerberus_tc.c
GO_SRC := cmd/cerberus/main.go
BUILD_DIR := build

.PHONY: all clean build bpf run deps ci ci-build ci-test docker-build docker-run help

all: bpf build

# Build eBPF program
bpf: $(BPF_OBJ)
$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c $(BPF_SRC) -o $(BPF_OBJ)

# Build Go binary
build: bpf
	CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o build/$(BINARY) $(GO_SRC)

# Run the program (requires sudo)
run: all
	sudo ./build/$(BINARY)

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ) build/$(BINARY)
	rm -rf build/

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Docker build
docker-build:
	docker build -t cerberus:latest .

# Docker run (privileged for BPF)
docker-run:
	docker run --rm -it \
		--privileged \
		--network host \
		--cap-add=SYS_ADMIN \
		--cap-add=NET_ADMIN \
		--cap-add=BPF \
		-v /sys/kernel/debug:/sys/kernel/debug:rw \
		-v /sys/fs/bpf:/sys/fs/bpf:rw \
		cerberus:latest

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CI/CD Targets
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Run all CI tests
ci: ci-build ci-test
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  All CI tests passed! ✓"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Build and verify across multiple distributions
ci-build:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  CI Build Tests (Multi-Distribution)"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@chmod +x .ci/build.sh
	@echo "→ Testing on Ubuntu 22.04..."
	docker build --quiet --build-arg BASE_IMAGE=ubuntu:22.04 -t cerberus-ci-ubuntu22 -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-ubuntu22 /workspace/.ci/build.sh
	@echo ""
	@echo "→ Testing on Ubuntu 24.04..."
	docker build --quiet --build-arg BASE_IMAGE=ubuntu:24.04 -t cerberus-ci-ubuntu24 -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-ubuntu24 /workspace/.ci/build.sh
	@echo ""
	@echo "→ Testing on Debian 12..."
	docker build --quiet --build-arg BASE_IMAGE=debian:12 -t cerberus-ci-debian -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-debian /workspace/.ci/build.sh
	@echo ""
	@echo "→ Testing on Arch Linux..."
	docker build --quiet --build-arg BASE_IMAGE=archlinux:latest -t cerberus-ci-arch -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-arch /workspace/.ci/build.sh
	@echo ""
	@echo "✓ All distribution builds passed!"

# Runtime tests (requires privileged containers)
ci-test:
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  CI Runtime Tests (Privileged Containers)"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@chmod +x .ci/test.sh
	@echo "→ Runtime test on Ubuntu 22.04..."
	docker run --rm --privileged --network host \
		-v $(PWD):/workspace \
		-v /sys/fs/bpf:/sys/fs/bpf:rw \
		cerberus-ci-ubuntu22 /workspace/.ci/test.sh
	@echo ""
	@echo "→ Runtime test on Ubuntu 24.04..."
	docker run --rm --privileged --network host \
		-v $(PWD):/workspace \
		-v /sys/fs/bpf:/sys/fs/bpf:rw \
		cerberus-ci-ubuntu24 /workspace/.ci/test.sh
	@echo ""
	@echo "✓ All runtime tests passed!"

# Quick CI - build only (faster)
ci-quick: ci-build

# Test specific distribution
ci-ubuntu22:
	@chmod +x .ci/build.sh .ci/test.sh
	docker build --build-arg BASE_IMAGE=ubuntu:22.04 -t cerberus-ci-ubuntu22 -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-ubuntu22 /workspace/.ci/build.sh
	docker run --rm --privileged --network host -v $(PWD):/workspace -v /sys/fs/bpf:/sys/fs/bpf:rw cerberus-ci-ubuntu22 /workspace/.ci/test.sh

ci-ubuntu24:
	@chmod +x .ci/build.sh .ci/test.sh
	docker build --build-arg BASE_IMAGE=ubuntu:24.04 -t cerberus-ci-ubuntu24 -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-ubuntu24 /workspace/.ci/build.sh
	docker run --rm --privileged --network host -v $(PWD):/workspace -v /sys/fs/bpf:/sys/fs/bpf:rw cerberus-ci-ubuntu24 /workspace/.ci/test.sh

ci-debian:
	@chmod +x .ci/build.sh .ci/test.sh
	docker build --build-arg BASE_IMAGE=debian:12 -t cerberus-ci-debian -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-debian /workspace/.ci/build.sh
	docker run --rm --privileged --network host -v $(PWD):/workspace -v /sys/fs/bpf:/sys/fs/bpf:rw cerberus-ci-debian /workspace/.ci/test.sh

ci-arch:
	@chmod +x .ci/build.sh .ci/test.sh
	docker build --build-arg BASE_IMAGE=archlinux:latest -t cerberus-ci-arch -f .ci/Dockerfile .
	docker run --rm -v $(PWD):/workspace cerberus-ci-arch /workspace/.ci/build.sh
	docker run --rm --privileged --network host -v $(PWD):/workspace -v /sys/fs/bpf:/sys/fs/bpf:rw cerberus-ci-arch /workspace/.ci/test.sh

# Clean CI artifacts
ci-clean:
	docker rmi -f cerberus-ci-ubuntu22 cerberus-ci-ubuntu24 cerberus-ci-debian cerberus-ci-arch 2>/dev/null || true
	rm -f cerberus-test.log

# Help
help:
	@echo "Cerberus Makefile - Available Targets:"
	@echo ""
	@echo "  Building:"
	@echo "    make all           - Build everything (eBPF + Go binary)"
	@echo "    make bpf           - Build eBPF program only"
	@echo "    make build         - Build Go binary only"
	@echo "    make clean         - Remove build artifacts"
	@echo "    make deps          - Download and tidy Go dependencies"
	@echo ""
	@echo "  Running:"
	@echo "    make run           - Build and run (requires sudo)"
	@echo "    make docker-build  - Build Docker image"
	@echo "    make docker-run    - Run in privileged Docker container"
	@echo ""
	@echo "  CI/CD:"
	@echo "    make ci            - Run all CI tests (build + runtime)"
	@echo "    make ci-build      - Build tests on all distributions"
	@echo "    make ci-test       - Runtime tests on all distributions"
	@echo "    make ci-quick      - Build tests only (faster)"
	@echo ""
	@echo "  CI/CD - Specific Distributions:"
	@echo "    make ci-ubuntu22   - Test on Ubuntu 22.04"
	@echo "    make ci-ubuntu24   - Test on Ubuntu 24.04"
	@echo "    make ci-debian     - Test on Debian 12"
	@echo "    make ci-arch       - Test on Arch Linux"
	@echo "    make ci-clean      - Remove CI Docker images"
	@echo ""
	@echo "  Help:"
	@echo "    make help          - Show this help message"
