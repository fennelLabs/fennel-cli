# Stage 1: Build the Rust binary
FROM rust:1.82 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin fennel-cli

# Stage 2: Create minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/fennel-cli /usr/local/bin/
EXPOSE 9031
CMD ["fennel-cli", "start-api"]
