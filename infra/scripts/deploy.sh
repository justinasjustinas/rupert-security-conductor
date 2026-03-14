#!/bin/bash
# Deployment script for Rupert Security Conductor
# Usage: ./deploy.sh <GCP_PROJECT_ID> [GCP_REGION] [IMAGE_TAG]
# Example: ./deploy.sh my-project europe-west1 build-20260314-120000

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GCP_PROJECT_ID=${1:-}
GCP_REGION=${2:-europe-west1}
IMAGE_TAG=${3:-}
SERVICE_NAME="rupert-security-conductor"
ARTIFACT_REGISTRY="security-conductor"
IMAGE_NAME="security-conductor"
CLOUD_RUN_SERVICE_ACCOUNT_ID="${CLOUD_RUN_SERVICE_ACCOUNT_ID:-rupert-security-conductor}"
GITHUB_ACTIONS_SERVICE_ACCOUNT_ID="${GITHUB_ACTIONS_SERVICE_ACCOUNT_ID:-rupert-github-actions}"
ACTIVE_GCLOUD_ACCOUNT=""

resolve_image_tag() {
  if [ -n "${IMAGE_TAG}" ]; then
    return
  fi

  local timestamp
  local git_sha

  timestamp=$(date -u +"%Y%m%d%H%M%S")
  git_sha=$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "manual")
  IMAGE_TAG="${git_sha}-${timestamp}"
}

require_command() {
  local command_name=$1
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name"
    exit 1
  fi
}

wait_for_secret_version() {
  local secret_name=$1
  local max_attempts=10
  local attempt=1

  while [ "$attempt" -le "$max_attempts" ]; do
    if gcloud secrets versions access latest --secret="$secret_name" >/dev/null 2>&1; then
      return 0
    fi

    echo "   Waiting for secret version to become available: ${secret_name} (attempt ${attempt}/${max_attempts})"
    sleep 2
    attempt=$((attempt + 1))
  done

  echo "Secret version for ${secret_name} was not available after waiting."
  exit 1
}

preflight_check() {
  local active_account

  echo "🔎 Running preflight checks..."

  require_command gcloud
  require_command terraform
  require_command docker

  if ! docker buildx version >/dev/null 2>&1; then
    echo "Docker buildx is required but not available."
    exit 1
  fi

  active_account=$(gcloud config get-value account 2>/dev/null || true)
  if [ -z "$active_account" ] || [ "$active_account" = "(unset)" ]; then
    echo "No active gcloud account is configured. Run: gcloud auth login"
    exit 1
  fi

  ACTIVE_GCLOUD_ACCOUNT="$active_account"

  echo "   Active gcloud account: $active_account"

  if ! gcloud projects describe "$GCP_PROJECT_ID" >/dev/null 2>&1; then
    echo "Cannot access GCP project '$GCP_PROJECT_ID' with account '$active_account'."
    exit 1
  fi

  if ! gcloud projects get-iam-policy "$GCP_PROJECT_ID" \
    --flatten="bindings[].members" \
    --filter="bindings.members:user:$active_account OR bindings.members:serviceAccount:$active_account" \
    --format="value(bindings.role)" >/dev/null 2>&1; then
    echo "Unable to read IAM policy for project '$GCP_PROJECT_ID'."
    echo "The deploying account likely lacks the bootstrap permissions documented in DEPLOYMENT.md."
    exit 1
  fi

  echo "   Verified project visibility and IAM policy read access."
  echo ""
}

import_if_exists() {
  local address=$1
  local import_id=$2

  if terraform state show "$address" >/dev/null 2>&1; then
    return 0
  fi

  echo "🔄 Importing existing resource into Terraform state: $address"
  terraform import "$address" "$import_id" >/dev/null
}

import_existing_resources() {
  local cloud_run_sa_email="${CLOUD_RUN_SERVICE_ACCOUNT_ID}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
  local github_actions_sa_email="${GITHUB_ACTIONS_SERVICE_ACCOUNT_ID}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

  echo "🔎 Checking for existing bootstrap resources to import..."

  if gcloud iam service-accounts describe "$cloud_run_sa_email" >/dev/null 2>&1; then
    import_if_exists \
      "google_service_account.cloud_run" \
      "projects/${GCP_PROJECT_ID}/serviceAccounts/${cloud_run_sa_email}"
  fi

  if gcloud artifacts repositories describe "$ARTIFACT_REGISTRY" --location="$GCP_REGION" >/dev/null 2>&1; then
    import_if_exists \
      "google_artifact_registry_repository.docker_repo" \
      "projects/${GCP_PROJECT_ID}/locations/${GCP_REGION}/repositories/${ARTIFACT_REGISTRY}"
  fi

  if gcloud secrets describe "rupert-gemini-api-key" >/dev/null 2>&1; then
    import_if_exists \
      "google_secret_manager_secret.gemini_api_key" \
      "projects/${GCP_PROJECT_ID}/secrets/rupert-gemini-api-key"
  fi

  if gcloud secrets describe "rupert-scan-api-token" >/dev/null 2>&1; then
    import_if_exists \
      "google_secret_manager_secret.scan_api_token" \
      "projects/${GCP_PROJECT_ID}/secrets/rupert-scan-api-token"
  fi

  if [ -n "${GITHUB_REPOSITORY_OWNER:-}" ] && [ -n "${GITHUB_REPOSITORY_NAME:-}" ]; then
    if gcloud iam service-accounts describe "$github_actions_sa_email" >/dev/null 2>&1; then
      import_if_exists \
        "google_service_account.github_actions[0]" \
        "projects/${GCP_PROJECT_ID}/serviceAccounts/${github_actions_sa_email}"
    fi
  fi
}

if [ -z "$GCP_PROJECT_ID" ]; then
  echo "Usage: ./deploy.sh <GCP_PROJECT_ID> [GCP_REGION] [IMAGE_TAG]"
  echo "Regions: europe-west1, us-central1, us-east1, asia-northeast1, etc."
  exit 1
fi

if [ -z "${GEMINI_API_KEY:-}" ]; then
  echo "GEMINI_API_KEY must be set before deployment."
  exit 1
fi

if [ -z "${SCAN_API_TOKEN:-}" ]; then
  echo "SCAN_API_TOKEN must be set before deployment."
  exit 1
fi

resolve_image_tag
preflight_check

echo "🚀 Deploying Rupert Security Conductor"
echo "   Project: $GCP_PROJECT_ID"
echo "   Region: $GCP_REGION"
echo "   Image Tag: $IMAGE_TAG"
echo ""

# Set project
gcloud config set project "$GCP_PROJECT_ID"

echo "ℹ️  Bootstrap permissions required on the deploying account:"
echo "   - roles/artifactregistry.admin"
echo "   - roles/secretmanager.admin"
echo "   - roles/run.admin"
echo "   - roles/iam.serviceAccountAdmin"
echo "   - roles/iam.securityAdmin"
echo ""

# Enable required APIs
echo "🔧 Enabling required GCP APIs..."
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  logging.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  --quiet

# Bootstrap Terraform-managed prerequisites first
echo "🏗️  Bootstrapping Terraform-managed prerequisites..."
cd infra/terraform
terraform init
import_existing_resources

TF_ARGS=(
  -auto-approve
  -var="gcp_project_id=${GCP_PROJECT_ID}"
  -var="gcp_region=${GCP_REGION}"
  -var="docker_image_tag=${IMAGE_TAG}"
)

if [ -n "${GITHUB_REPOSITORY_OWNER:-}" ] && [ -n "${GITHUB_REPOSITORY_NAME:-}" ]; then
  echo "🔐 Configuring GitHub Actions Workload Identity Federation for ${GITHUB_REPOSITORY_OWNER}/${GITHUB_REPOSITORY_NAME}..."
  TF_ARGS+=(
    -var="github_repository_owner=${GITHUB_REPOSITORY_OWNER}"
    -var="github_repository_name=${GITHUB_REPOSITORY_NAME}"
  )
fi

terraform apply "${TF_ARGS[@]}" \
  -target=google_artifact_registry_repository.docker_repo \
  -target=google_secret_manager_secret.gemini_api_key \
  -target=google_secret_manager_secret.scan_api_token \
  -target=google_service_account.cloud_run

echo "🔐 Adding Gemini API key to Secret Manager..."
gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"
wait_for_secret_version "rupert-gemini-api-key"

echo "🔐 Adding scan API token to Secret Manager..."
gcloud secrets versions add rupert-scan-api-token --data-file=- <<< "$SCAN_API_TOKEN"
wait_for_secret_version "rupert-scan-api-token"

# Authenticate Docker for Artifact Registry (needed for buildx)
echo "🔐 Configuring Artifact Registry authentication..."
gcloud auth configure-docker "${GCP_REGION}-docker.pkg.dev"

# Build and push Docker image directly for single architecture
echo "📦 Building and pushing Docker image (single-arch amd64)..."
echo "   Dockerfile: ${REPO_ROOT}/Dockerfile"
echo "   Context: ${REPO_ROOT}"
docker buildx build \
  --file "${REPO_ROOT}/Dockerfile" \
  --push \
  --platform linux/amd64 \
  --no-cache \
  -t "${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}" \
  "${REPO_ROOT}"

# Apply the full Terraform stack
echo "🏗️  Applying full Terraform configuration..."
cd "${REPO_ROOT}/infra/terraform"
terraform apply "${TF_ARGS[@]}"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📋 Next steps:"
echo "1. Get the service URL:"
terraform output cloud_run_service_url
echo ""
echo "2. Test /scan with the bearer token you deployed:"
echo "   curl -X POST \$(terraform output -raw cloud_run_service_url)/scan \\"
echo "     -H \"Authorization: Bearer \$SCAN_API_TOKEN\" \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -d '{\"repository\":\"test-repo\",\"branch\":\"main\",\"commit_hash\":\"abc123\",\"code_diff\":\"- const sql = \\\"SELECT * FROM users WHERE id = \\\" + userId;\",\"author\":\"manual\"}'"
echo ""
if [ -n "${GITHUB_REPOSITORY_OWNER:-}" ] && [ -n "${GITHUB_REPOSITORY_NAME:-}" ]; then
  echo "3. Add these GitHub Actions secrets:"
  echo "   GCP_PROJECT_ID=${GCP_PROJECT_ID}"
  echo "   WIF_PROVIDER=$(terraform output -raw github_workload_identity_provider)"
  echo "   WIF_SERVICE_ACCOUNT=$(terraform output -raw github_actions_service_account_email)"
  echo ""
fi

echo "4. Optional least-privilege cleanup for the bootstrap account (${ACTIVE_GCLOUD_ACCOUNT}):"
echo "   After verifying deploys work through GitHub Actions, remove the temporary bootstrap roles:"
echo "   gcloud projects remove-iam-policy-binding ${GCP_PROJECT_ID} --member=\"user:${ACTIVE_GCLOUD_ACCOUNT}\" --role=\"roles/artifactregistry.admin\""
echo "   gcloud projects remove-iam-policy-binding ${GCP_PROJECT_ID} --member=\"user:${ACTIVE_GCLOUD_ACCOUNT}\" --role=\"roles/secretmanager.admin\""
echo "   gcloud projects remove-iam-policy-binding ${GCP_PROJECT_ID} --member=\"user:${ACTIVE_GCLOUD_ACCOUNT}\" --role=\"roles/run.admin\""
echo "   gcloud projects remove-iam-policy-binding ${GCP_PROJECT_ID} --member=\"user:${ACTIVE_GCLOUD_ACCOUNT}\" --role=\"roles/iam.serviceAccountAdmin\""
echo "   gcloud projects remove-iam-policy-binding ${GCP_PROJECT_ID} --member=\"user:${ACTIVE_GCLOUD_ACCOUNT}\" --role=\"roles/iam.securityAdmin\""
