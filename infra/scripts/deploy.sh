#!/bin/bash
# Deployment script for Rupert Security Conductor
# Usage: ./deploy.sh <GCP_PROJECT_ID> [GCP_REGION] [IMAGE_TAG]

set -e

GCP_PROJECT_ID=${1:-}
GCP_REGION=${2:-eu-west1}
IMAGE_TAG=${3:-latest}
SERVICE_NAME="rupert-security-conductor"
ARTIFACT_REGISTRY="security-conductor"
IMAGE_NAME="security-conductor"

if [ -z "$GCP_PROJECT_ID" ]; then
  echo "Usage: ./deploy.sh <GCP_PROJECT_ID> [GCP_REGION] [IMAGE_TAG]"
  exit 1
fi

echo "🚀 Deploying Rupert Security Conductor"
echo "   Project: $GCP_PROJECT_ID"
echo "   Region: $GCP_REGION"
echo "   Image Tag: $IMAGE_TAG"
echo ""

# Set project
gcloud config set project "$GCP_PROJECT_ID"

# Build Docker image
echo "📦 Building Docker image..."
docker build -t "${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}" .

# Authenticate Docker for Artifact Registry
echo "🔐 Authenticating Docker for Artifact Registry..."
gcloud auth configure-docker "${GCP_REGION}-docker.pkg.dev"

# Push to Artifact Registry
echo "📤 Pushing image to Artifact Registry..."
docker push "${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

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
