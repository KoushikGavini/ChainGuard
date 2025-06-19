# Build stage
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

# Create app directory
WORKDIR /usr/src/chainguard

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy main to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    openssl \
    tini

# Create non-root user
RUN addgroup -g 1000 chainguard && \
    adduser -D -u 1000 -G chainguard chainguard

# Copy binary from builder
COPY --from=builder /usr/src/chainguard/target/release/chainguard /usr/local/bin/chainguard

# Create working directory
WORKDIR /workspace
RUN chown -R chainguard:chainguard /workspace

# Switch to non-root user
USER chainguard

# Use tini as entrypoint to handle signals properly
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["chainguard", "--help"]

# Labels
LABEL org.opencontainers.image.title="ChainGuard"
LABEL org.opencontainers.image.description="Advanced security analysis for blockchain platforms"
LABEL org.opencontainers.image.vendor="ChainGuard"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/KoushikGavini/ChainGuard" 