# Build stage
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    linux-tools-generic \
    pkg-config \
    git \
    wget \
    ca-certificates \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN wget https://go.dev/dl/go1.25.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.4.linux-amd64.tar.gz && \
    rm go1.25.4.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make bpf
RUN CGO_CFLAGS="-I/usr/include" \
    CGO_LDFLAGS="$(pkg-config --libs libbpf)" \
    go build -o cerberus cmd/cerberus/main.go

# Runtime stage
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    libelf-dev \
    libbpf-dev \
    zlib1g \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/cerberus /app/cerberus
COPY --from=builder /app/monitor_xdp.o /app/monitor_xdp.o
RUN mkdir -p /app/data
CMD ["./cerberus"]