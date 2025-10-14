#!/bin/bash
set -e

echo "🔄 Reverting to original working Bitwise encoder..."

# Build the Docker image
echo "🏗️  Building fennel-cli with original hashmap_to_json_string..."
docker build -t fennelacr531.azurecr.io/fennel-cli-api:v1.1.1-original-bitwise .

# Push to ACR
echo "📤 Pushing to Azure Container Registry..."
docker push fennelacr531.azurecr.io/fennel-cli-api:v1.1.1-original-bitwise

# Update the deployment
echo "🚀 Updating Kubernetes deployment..."
kubectl set image deployment/fennel-cli-api -n fennel-api \
  fennel-cli-api=fennelacr531.azurecr.io/fennel-cli-api:v1.1.1-original-bitwise

# Wait for rollout
echo "⏳ Waiting for rollout to complete..."
kubectl rollout status deployment/fennel-cli-api -n fennel-api

echo "✅ Deployment complete! Original Bitwise encoder restored."
echo "🧪 Test F messages with annotations should now work."
