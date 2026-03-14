# Deployment Guide

This is the step-by-step deployment path for Rupert Security Conductor on GCP Cloud Run.

## Before You Start

You need:
- `gcloud`
- Terraform
- Docker with `buildx`
- a GCP project with billing enabled
- a Gemini API key

Default region used in this repo:

```bash
export GCP_REGION="europe-west1"
```

## Step 1: Create or Select a GCP Project

```bash
export GCP_PROJECT_ID="rupert-security-conductor"

gcloud projects create "$GCP_PROJECT_ID" \
  --display-name="Rupert Security Conductor" || true

gcloud config set project "$GCP_PROJECT_ID"
```

If the project already exists, the `create` command can fail safely and you can continue.

## Step 2: Authenticate gcloud

```bash
gcloud auth login
gcloud config get-value account
```

The account shown here is the one that will run the first deployment.

## Step 3: Enable Required GCP APIs

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  logging.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com
```

## Step 4: Grant Temporary Bootstrap IAM

The first deploy needs a human account with enough permission to create:
- Artifact Registry
- Secret Manager resources
- service accounts
- Cloud Run resources and IAM
- GitHub Workload Identity Federation resources

Set the account you saw in Step 2:

```bash
export BOOTSTRAP_ACCOUNT="you@example.com"
```

Grant the temporary roles:

```bash
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/artifactregistry.admin"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/secretmanager.admin"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/run.admin"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/iam.serviceAccountAdmin"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/iam.securityAdmin"
```

These are bootstrap roles. You should remove them later after GitHub Actions deploys are working.

## Step 5: Get a Gemini API Key

Create a key in Google AI Studio:
- https://aistudio.google.com/app/apikey

Then export it:

```bash
export GEMINI_API_KEY="your-api-key"
```

## Step 6: Set GitHub Repository Coordinates

For a personal repo, `GITHUB_REPOSITORY_OWNER` is your GitHub username.

```bash
export GITHUB_REPOSITORY_OWNER="your-github-username"
export GITHUB_REPOSITORY_NAME="rupert-security-conductor"
```

These values are used to scope GitHub Workload Identity Federation to one repository.

## Step 7: Run the Deployment Script

From the repo root:

```bash
cd /Users/justinas/Workspace/rupert-security-conductor
bash infra/scripts/deploy.sh "$GCP_PROJECT_ID" "$GCP_REGION"
```

What `deploy.sh` does:
1. Runs preflight checks.
2. Enables required APIs.
3. Imports existing bootstrap resources into Terraform state if they already exist.
4. Creates bootstrap infrastructure with Terraform.
5. Writes the current `GEMINI_API_KEY` into Secret Manager.
6. Builds and pushes the Docker image.
7. Applies the full Terraform stack.

## Step 8: Verify the Deployment

Get the URL:

```bash
SERVICE_URL=$(gcloud run services describe rupert-security-conductor \
  --region="$GCP_REGION" \
  --format='value(status.url)')

echo "$SERVICE_URL"
```

Check health:

```bash
curl "$SERVICE_URL/health"
```

Run a sample scan:

```bash
curl -X POST "$SERVICE_URL/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "test-repo",
    "branch": "main",
    "commit_hash": "abc123",
    "code_diff": "- const sql = \"SELECT * FROM users WHERE id = \" + userId;",
    "author": "test@example.com"
  }'
```

## Step 9: Configure GitHub Actions Secrets

After `deploy.sh` finishes, it prints the values you need.

You can also fetch them manually:

```bash
cd /Users/justinas/Workspace/rupert-security-conductor/infra/terraform
terraform output -raw github_workload_identity_provider
terraform output -raw github_actions_service_account_email
```

Add these in GitHub:
`Settings` → `Secrets and variables` → `Actions`

Create these repository secrets:
- `GCP_PROJECT_ID`
- `WIF_PROVIDER`
- `WIF_SERVICE_ACCOUNT`

## Step 10: Test CI/CD

Push a commit to `main` or `develop`.

The workflow at [.github/workflows/ci-cd.yml](/Users/justinas/Workspace/rupert-security-conductor/.github/workflows/ci-cd.yml) should:
- run tests
- authenticate to GCP with WIF
- build and push the image
- deploy to Cloud Run on pushes where the workflow conditions match

## Step 11: Remove Temporary Bootstrap IAM

After GitHub Actions deploys are confirmed working, remove the temporary human bootstrap roles:

```bash
gcloud projects remove-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/artifactregistry.admin"

gcloud projects remove-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/secretmanager.admin"

gcloud projects remove-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/run.admin"

gcloud projects remove-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/iam.serviceAccountAdmin"

gcloud projects remove-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$BOOTSTRAP_ACCOUNT" \
  --role="roles/iam.securityAdmin"
```

## Webhooks

GitHub:
1. Open your repository settings.
2. Go to `Webhooks`.
3. Add a webhook pointing to:
   `https://<SERVICE_URL>/webhook/github`

Bitbucket:
1. Open repository settings.
2. Go to `Webhooks`.
3. Add a webhook pointing to:
   `https://<SERVICE_URL>/webhook/bitbucket`

## Troubleshooting

Wrong gcloud account:

```bash
gcloud auth list
gcloud config get-value account
```

Get the service URL again:

```bash
gcloud run services describe rupert-security-conductor \
  --region="$GCP_REGION" \
  --format='value(status.url)'
```

Read logs:

```bash
gcloud logging read "resource.labels.service_name=rupert-security-conductor" \
  --limit 20 \
  --format "table(timestamp,severity,jsonPayload.message)"
```

Re-run Terraform outputs:

```bash
cd /Users/justinas/Workspace/rupert-security-conductor/infra/terraform
terraform output
```

Destroy managed resources:

```bash
cd /Users/justinas/Workspace/rupert-security-conductor/infra/terraform
terraform destroy -auto-approve \
  -var="gcp_project_id=$GCP_PROJECT_ID" \
  -var="gcp_region=$GCP_REGION"
```
