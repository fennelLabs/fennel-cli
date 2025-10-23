#!/bin/bash
set -e

echo "🚀 Deploying fennel-cli v1.1.3 with Test Message Support"
echo "========================================================"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
ACR_NAME="fennelacr531"
IMAGE_NAME="fennel-cli"
NEW_VERSION="v1.1.3-test-message-fix-arm64"
NAMESPACE="fennel-api"
DEPLOYMENT="fennel-cli-api"

# Step 1: Login to Azure Container Registry
print_status "Logging into Azure Container Registry..."
az acr login --name $ACR_NAME || { print_error "Failed to login to ACR"; exit 1; }
print_success "Logged into ACR"

# Step 2: Create a Dockerfile that updates paths and builds
print_status "Creating Dockerfile with corrected dependency paths..."

cat > /tmp/Dockerfile.fennel-cli-v1.1.3 << 'EOF'
# Stage 1: Build the Rust binary with all dependencies
FROM rust:1.82 AS builder
WORKDIR /build

# Copy all dependency sources
COPY fennel-lib-updated /build/fennel-lib-updated
COPY whiteflag-rust /build/whiteflag-rust
COPY fennel-deploy/fennel-cli /build/fennel-cli

# Update Cargo.toml to use correct paths within the container
WORKDIR /build/fennel-cli
RUN sed -i 's|path = "../../fennel-lib-updated"|path = "../fennel-lib-updated"|g' Cargo.toml && \
    sed -i 's|path = "../../whiteflag-rust"|path = "../whiteflag-rust"|g' Cargo.toml && \
    sed -i 's|path = "../../whiteflag-rust/wf_cli"|path = "../whiteflag-rust/wf_cli"|g' Cargo.toml && \
    echo "Updated Cargo.toml dependencies:" && \
    grep "^fennel-lib\|^whiteflag-rust\|^wf_cli" Cargo.toml

# Build the binary
RUN cargo build --release --bin fennel-cli

# Stage 2: Create minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/fennel-cli/target/release/fennel-cli /usr/local/bin/
RUN chmod +x /usr/local/bin/fennel-cli
EXPOSE 9031
CMD ["fennel-cli", "start-api"]
EOF

# Step 3: Build from parent directory to include dependencies
print_status "Building Docker image for ARM64 from source..."
print_warning "This will take 5-10 minutes as it compiles Rust code for ARM64..."

cd /home/neurosx/DEVSPACE

docker buildx build \
    --platform linux/arm64 \
    -t ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${NEW_VERSION} \
    -f /tmp/Dockerfile.fennel-cli-v1.1.3 \
    --push \
    . || { print_error "Docker build failed"; exit 1; }

print_success "Docker image built and pushed: ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${NEW_VERSION}"

# Step 4: Update the Kubernetes deployment
print_status "Updating Kubernetes deployment..."

kubectl set image deployment/${DEPLOYMENT} \
    fennel-cli-api=${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${NEW_VERSION} \
    -n ${NAMESPACE} || { print_error "Failed to update deployment"; exit 1; }

print_success "Deployment updated"

# Step 5: Wait for rollout
print_status "Waiting for rollout to complete (up to 10 minutes)..."
kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE} --timeout=10m

print_success "✅ Deployment complete!"
print_status "📋 Check logs with: kubectl logs -f deployment/${DEPLOYMENT} -n ${NAMESPACE}"
print_status "🧪 Run integration tests: cd /home/neurosx/DEVSPACE/fennel-deploy/fennel-service-api && ./api_integration_test.sh"
