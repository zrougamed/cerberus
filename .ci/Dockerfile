# Multi-distribution CI Dockerfile for Cerberus
# Supports: Ubuntu 22.04, Ubuntu 24.04, Debian 12, Arch Linux
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=linux

# Install dependencies based on distribution
RUN if command -v apt-get > /dev/null 2>&1; then \
        # Debian/Ubuntu
        apt-get update && \
        apt-get install -y \
            clang \
            llvm \
            make \
            git \
            wget \
            ca-certificates \
            libbpf-dev \
            linux-headers-generic \
            file \
            iproute2 \
            && rm -rf /var/lib/apt/lists/*; \
    elif command -v pacman > /dev/null 2>&1; then \
        # Arch Linux
        pacman -Syu --noconfirm && \
        pacman -S --noconfirm \
            clang \
            llvm \
            make \
            git \
            wget \
            ca-certificates \
            file \
            base-devel \
            libbpf \
            linux-headers \
            iproute2; \
    fi

# Install Go 1.25
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then GOARCH="arm64"; \
    elif [ "$ARCH" = "armv7l" ]; then GOARCH="armv6l"; \
    else GOARCH="amd64"; fi && \
    wget -q https://go.dev/dl/go1.25.4.linux-${GOARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.25.4.linux-${GOARCH}.tar.gz && \
    rm go1.25.4.linux-${GOARCH}.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

WORKDIR /workspace

# Pre-download Go dependencies to cache them
COPY go.mod go.sum ./
RUN go mod download

CMD ["/bin/sh"]