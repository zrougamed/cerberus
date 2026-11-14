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
        apt-get install -y --no-install-recommends \
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

# Install Go from go.dev, verified against the published SHA-256.
ARG GO_VERSION=1.27.4
ARG GO_SHA256_AMD64=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
ARG GO_SHA256_ARM64=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
RUN set -e; ARCH=$(uname -m); \
    case "$ARCH" in \
        x86_64) GOARCH=amd64; SUM=$GO_SHA256_AMD64 ;; \
        aarch64) GOARCH=arm64; SUM=$GO_SHA256_ARM64 ;; \
        *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    TARBALL="go${GO_VERSION}.linux-${GOARCH}.tar.gz"; \
    wget -q "https://go.dev/dl/${TARBALL}"; \
    echo "${SUM}  ${TARBALL}" | sha256sum -c -; \
    tar -C /usr/local -xzf "${TARBALL}"; \
    rm "${TARBALL}"

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

WORKDIR /workspace

# Pre-download Go dependencies to cache them
COPY go.mod go.sum ./
RUN go mod download && go mod verify

CMD ["/bin/sh"]