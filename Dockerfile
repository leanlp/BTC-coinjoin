# Build Stage
FROM nvidia/cuda:12.2.0-devel-ubuntu22.04 AS builder

# Install Go
RUN apt-get update && apt-get install -y wget gcc && \
    wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

WORKDIR /app

# Copy Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Compile CUDA Math Kernel library
WORKDIR /app/internal/cuda
RUN nvcc -c -O3 kernel.cu -o kernel.o && \
    ar rcs libkernel.a kernel.o

# Build the Go application
WORKDIR /app
RUN CGO_ENABLED=1 GOOS=linux go build -tags=cuda -o btc-coinjoin-cuda-analytics ./cmd/engine

# Runtime Stage
FROM nvidia/cuda:12.2.0-runtime-ubuntu22.04

WORKDIR /app

# Install standard CA certificates for HTTPS requests
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/btc-coinjoin-cuda-analytics .
# Copy static web assets
COPY --from=builder /app/public ./public

# Expose default port
EXPOSE 5339

# Run the binary
CMD ["./btc-coinjoin-cuda-analytics"]
