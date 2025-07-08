# Build stage
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

# Create app directory
WORKDIR /usr/src/shieldcontract

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
RUN addgroup -g 1000 shieldcontract && \
    adduser -D -u 1000 -G shieldcontract shieldcontract

# Copy binary from builder
COPY --from=builder /usr/src/shieldcontract/target/release/shieldcontract /usr/local/bin/shieldcontract

# Create working directory
WORKDIR /workspace
RUN chown -R shieldcontract:shieldcontract /workspace

# Switch to non-root user
USER shieldcontract

# Use tini as entrypoint to handle signals properly
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["shieldcontract", "--help"]

# Labels
LABEL org.opencontainers.image.title="ShieldContract"
LABEL org.opencontainers.image.description="Advanced security analysis for blockchain platforms"
LABEL org.opencontainers.image.vendor="ShieldContract"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/KoushikGavini/ShieldContract" 