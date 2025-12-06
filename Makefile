CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

BINARY := build/cerberus
BPF_OBJ := build/arp_xdp.o
BPF_SRC := ebpf/arp_xdp.c
GO_SRC := cmd/cerberus/main.go

.PHONY: all clean build bpf run

all: bpf build

# Build eBPF program
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	mkdir -p build
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c $(BPF_SRC) -o $(BPF_OBJ)

# Build Go binary
build: bpf
	$(GO) build -o $(BINARY) $(GO_SRC)

# Run the program (requires sudo)
run: all
	cd build && sudo ./$(BINARY)

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ) $(BINARY)

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy