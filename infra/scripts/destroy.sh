#!/bin/bash
# Destroy script for Rupert Security Conductor infrastructure.
# Usage: ./destroy.sh <GCP_PROJECT_ID> [GCP_REGION] [--yes]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GCP_PROJECT_ID=${1:-}
GCP_REGION=${2:-europe-west1}
CONFIRM_FLAG=${3:-}
SERVICE_NAME="${CLOUD_RUN_SERVICE_NAME:-rupert-security-conductor}"
ARTIFACT_REGISTRY="${ARTIFACT_REGISTRY_REPO:-security-conductor}"
CLOUD_RUN_SERVICE_ACCOUNT_ID="${CLOUD_RUN_SERVICE_ACCOUNT_ID:-rupert-security-conductor}"
GITHUB_ACTIONS_SERVICE_ACCOUNT_ID="${GITHUB_ACTIONS_SERVICE_ACCOUNT_ID:-rupert-github-actions}"
GITHUB_WORKLOAD_IDENTITY_POOL_ID="${GITHUB_WORKLOAD_IDENTITY_POOL_ID:-github-actions}"
GITHUB_WORKLOAD_IDENTITY_PROVIDER_ID="${GITHUB_WORKLOAD_IDENTITY_PROVIDER_ID:-github-provider}"

require_command() {
  local command_name=$1
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name"
    exit 1
  fi
}

preflight_check() {
  local active_account

  echo "🔎 Running destroy preflight checks..."

  require_command gcloud
  require_command terraform

  active_account=$(gcloud config get-value account 2>/dev/null || true)
  if [ -z "$active_account" ] || [ "$active_account" = "(unset)" ]; then
    echo "No active gcloud account is configured. Run: gcloud auth login"
    exit 1
  fi

  echo "   Active gcloud account: $active_account"

  if ! gcloud projects describe "$GCP_PROJECT_ID" >/dev/null 2>&1; then
    echo "Cannot access GCP project '$GCP_PROJECT_ID' with account '$active_account'."
    exit 1
  fi
}

confirm_destroy() {
  if [ "$CONFIRM_FLAG" = "--yes" ]; then
    return 0
  fi

  local response
  echo "This will destroy Rupert Security Conductor infrastructure in project '${GCP_PROJECT_ID}' and region '${GCP_REGION}'."
  echo "It will delete the Cloud Run service, Artifact Registry repo, app secrets, service accounts, and GitHub WIF resources created by this repo."
  printf "Type the project id to continue: "
  read -r response

  if [ "$response" != "$GCP_PROJECT_ID" ]; then
    echo "Confirmation did not match. Aborting."
    exit 1
  fi
}

delete_if_exists() {
  "$@" >/dev/null 2>&1 || true
}

if [ -z "$GCP_PROJECT_ID" ]; then
  echo "Usage: ./destroy.sh <GCP_PROJECT_ID> [GCP_REGION] [--yes]"
  exit 1
fi

preflight_check
confirm_destroy

echo "🧨 Destroying Rupert Security Conductor infrastructure"
echo "   Project: $GCP_PROJECT_ID"
echo "   Region: $GCP_REGION"
echo ""

gcloud config set project "$GCP_PROJECT_ID" >/dev/null

cd "${REPO_ROOT}/infra/terraform"
terraform init >/dev/null

TF_ARGS=(
  -auto-approve
  -var="gcp_project_id=${GCP_PROJECT_ID}"
  -var="gcp_region=${GCP_REGION}"
)

if [ -n "${GITHUB_REPOSITORY_OWNER:-}" ] && [ -n "${GITHUB_REPOSITORY_NAME:-}" ]; then
  TF_ARGS+=(
    -var="github_repository_owner=${GITHUB_REPOSITORY_OWNER}"
    -var="github_repository_name=${GITHUB_REPOSITORY_NAME}"
  )
fi

echo "🏗️  Running Terraform destroy..."
terraform destroy "${TF_ARGS[@]}" || true

echo "🧹 Running best-effort cleanup for any remaining named resources..."

delete_if_exists gcloud run services delete "$SERVICE_NAME" --region="$GCP_REGION" --quiet
delete_if_exists gcloud artifacts repositories delete "$ARTIFACT_REGISTRY" --location="$GCP_REGION" --quiet

delete_if_exists gcloud secrets delete "rupert-gemini-api-key" --quiet
delete_if_exists gcloud secrets delete "rupert-scan-api-token" --quiet
delete_if_exists gcloud secrets delete "rupert-github-webhook-secret" --quiet
delete_if_exists gcloud secrets delete "rupert-bitbucket-webhook-secret" --quiet

delete_if_exists gcloud iam service-accounts delete \
  "${CLOUD_RUN_SERVICE_ACCOUNT_ID}@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --quiet

delete_if_exists gcloud iam service-accounts delete \
  "${GITHUB_ACTIONS_SERVICE_ACCOUNT_ID}@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --quiet

delete_if_exists gcloud iam workload-identity-pools providers delete \
  "$GITHUB_WORKLOAD_IDENTITY_PROVIDER_ID" \
  --location="global" \
  --workload-identity-pool="$GITHUB_WORKLOAD_IDENTITY_POOL_ID" \
  --quiet

delete_if_exists gcloud iam workload-identity-pools delete \
  "$GITHUB_WORKLOAD_IDENTITY_POOL_ID" \
  --location="global" \
  --quiet

echo ""
echo "✅ Destroy complete."
echo "If you want a fresh redeploy later, rerun:"
echo "   bash infra/scripts/deploy.sh \"$GCP_PROJECT_ID\" \"$GCP_REGION\""
