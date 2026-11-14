# Build stage. Base images are pinned by digest; bump tag and digest together.
FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

# Install only what we need for BPF compilation
RUN apk add --no-cache \
    clang \
    llvm \
    build-base \
    libbpf-dev \
    linux-headers \
    make

ENV GOCACHE=/root/.cache/go-build
ENV GOMODCACHE=/go/pkg/mod

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build eBPF program
RUN make bpf

# Build metadata is passed in from the caller (Makefile / CI workflow). The
# .git tree is not present in the build context (see .dockerignore), so we
# never shell out to git here.
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Build Go binary with version metadata stamped via ldflags.
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X github.com/zrougamed/cerberus/internal/version.Commit=${COMMIT} -X github.com/zrougamed/cerberus/internal/version.Date=${BUILD_DATE}" \
    -o cerberus cmd/cerberus/main.go

# Runtime stage
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# Install minimal runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    iproute2

WORKDIR /app

# Copy compiled artifacts
COPY --from=builder /app/cerberus /app/cerberus
COPY --from=builder /app/build/cerberus_tc.o /app/cerberus_tc.o

# Create data directory. The process stays root: attaching TC/BPF programs
# needs CAP_BPF/CAP_NET_ADMIN (see SECURITY-EXCEPTIONS.md).
RUN mkdir -p -m 0750 /app/data

CMD ["./cerberus"]
