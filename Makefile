CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

BINARY := cerberus
BPF_OBJ := monitor_xdp.o
BPF_SRC := ebpf/monitor_xdp.c
GO_SRC := cmd/cerberus/main.go

.PHONY: all clean build bpf run

all: bpf build

# Build eBPF program
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c $(BPF_SRC) -o $(BPF_OBJ)

# Build Go binary
build: bpf
	CGO_CFLAGS="-I/usr/include" \
	CGO_LDFLAGS="-lbpf -lelf -lz" \
	$(GO) build -o $(BINARY) $(GO_SRC)

# Run the program (requires sudo)
run: all
	sudo ./$(BINARY)

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ) $(BINARY)

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy