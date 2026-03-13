#!/bin/bash
# Deployment script for Rupert Security Conductor
# Usage: ./deploy.sh <GCP_PROJECT_ID> [GCP_REGION] [IMAGE_TAG]
# Example: ./deploy.sh my-project europe-west1 latest

set -e

GCP_PROJECT_ID=${1:-}
GCP_REGION=${2:-europe-west1}
IMAGE_TAG=${3:-latest}
SERVICE_NAME="rupert-security-conductor"
ARTIFACT_REGISTRY="security-conductor"
IMAGE_NAME="security-conductor"

if [ -z "$GCP_PROJECT_ID" ]; then
  echo "Usage: ./deploy.sh <GCP_PROJECT_ID> [GCP_REGION] [IMAGE_TAG]"
  echo "Regions: europe-west1, us-central1, us-east1, asia-northeast1, etc."
  exit 1
fi

echo "🚀 Deploying Rupert Security Conductor"
echo "   Project: $GCP_PROJECT_ID"
echo "   Region: $GCP_REGION"
echo "   Image Tag: $IMAGE_TAG"
echo ""

# Set project
gcloud config set project "$GCP_PROJECT_ID"

# Enable Artifact Registry API
echo "🔧 Enabling Artifact Registry API..."
gcloud services enable artifactregistry.googleapis.com --quiet

# Create Artifact Registry repository (ignore if already exists)
echo "📦 Creating Artifact Registry repository..."
gcloud artifacts repositories create "$ARTIFACT_REGISTRY" \
  --repository-format=docker \
  --location="$GCP_REGION" \
  --quiet 2>/dev/null || true

# Authenticate Docker for Artifact Registry (needed for buildx)
echo "🔐 Configuring Artifact Registry authentication..."
gcloud auth configure-docker "${GCP_REGION}-docker.pkg.dev"

# Build and push Docker image directly for single architecture
echo "📦 Building and pushing Docker image (single-arch amd64)..."
docker buildx build --push --platform linux/amd64 --no-cache -t "${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}" .

# Apply Terraform
echo "🏗️  Applying Terraform configuration..."
cd infra/terraform
terraform init
terraform apply -auto-approve \
  -var="gcp_project_id=${GCP_PROJECT_ID}" \
  -var="gcp_region=${GCP_REGION}" \
  -var="docker_image_tag=${IMAGE_TAG}"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📋 Next steps:"
echo "1. Set the Gemini API key:"
echo "   gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< \"\$GEMINI_API_KEY\""
echo ""
echo "2. Get the service URL:"
terraform output cloud_run_service_url
