# Deployment Guide

This is the step-by-step deployment path for Rupert Security Conductor on GCP Cloud Run.

## Before You Start

You need:
- `gcloud`
- Terraform
- Docker with `buildx`
- a GCP project with billing enabled
- a Gemini API key
- a bearer token for manual `/scan` access
- a GitHub personal access token (for webhook diff fetching)
- a GCS bucket name for scan result persistence

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

## Step 6: Set a /scan Bearer Token

Choose a long random token for manual testing of `/scan`:

```bash
export SCAN_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

The deployed app requires:

```bash
Authorization: Bearer $SCAN_API_TOKEN
```

for direct calls to `/scan`. If `SCAN_API_TOKEN` is not set and `SCAN_AUTH_DISABLED` is
not `true`, the endpoint returns 503.

## Step 6a: Set Webhook Secrets

Generate a separate secret for each webhook source:

```bash
export GITHUB_WEBHOOK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export BITBUCKET_WEBHOOK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

These are used to verify the HMAC-SHA256 signatures on incoming webhook payloads.
The app rejects webhooks if the matching secret env var is not configured.

You will enter these same values when configuring the webhook in GitHub/Bitbucket
(see the Webhooks section below).

## Step 6b: Set a GitHub Token

The webhook handler fetches the commit diff from the GitHub API automatically.
Without a token, public-repo diffs work (unauthenticated) but rate limits are tighter.
Private repos require a token with the `repo` read scope.

```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

## Step 6b: Create a GCS Bucket for Scan Persistence

Scan results (JSON) and Markdown reports are stored under
`gs://<bucket>/scans/<scan_id>/` after each run. Create the bucket:

```bash
export GCS_BUCKET_NAME="rupert-scans-$GCP_PROJECT_ID"

gcloud storage buckets create "gs://$GCS_BUCKET_NAME" \
  --location="$GCP_REGION" \
  --uniform-bucket-level-access
```

Then grant the Cloud Run service account write access:

```bash
gcloud storage buckets add-iam-policy-binding "gs://$GCS_BUCKET_NAME" \
  --member="serviceAccount:rupert-security-conductor@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/storage.objectCreator"
```

## Step 7: Set GitHub Repository Coordinates

For a personal repo, `GITHUB_REPOSITORY_OWNER` is your GitHub username.

```bash
export GITHUB_REPOSITORY_OWNER="your-github-username"
export GITHUB_REPOSITORY_NAME="rupert-security-conductor"
```

These values are used to scope GitHub Workload Identity Federation to one repository.

## Step 8: Run the Deployment Script

From the repo root:

```bash
cd rupert-security-conductor
bash infra/scripts/deploy.sh "$GCP_PROJECT_ID" "$GCP_REGION"
```

If you do not pass an image tag, `deploy.sh` now generates a unique one for
each deploy using the current git SHA and a UTC timestamp. That guarantees a
new Cloud Run revision when code changes.

What `deploy.sh` does:
1. Runs preflight checks.
2. Enables required APIs.
3. Imports existing bootstrap resources into Terraform state if they already exist.
4. Creates bootstrap infrastructure with Terraform.
5. Writes the current `GEMINI_API_KEY`, `SCAN_API_TOKEN`, `GITHUB_TOKEN`, and `GCS_BUCKET_NAME` into Secret Manager.
6. Builds and pushes the Docker image.
7. Applies the full Terraform stack.

## Step 9: Verify the Deployment

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
  -H "Authorization: Bearer $SCAN_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "test-repo",
    "branch": "main",
    "commit_hash": "abc123",
    "code_diff": "- const sql = \"SELECT * FROM users WHERE id = \" + userId;",
    "author": "test@example.com"
  }'
```

## Step 10: Configure GitHub Actions Secrets

After `deploy.sh` finishes, it prints the values you need.

You can also fetch them manually:

```bash
cd infra/terraform
terraform output -raw github_workload_identity_provider
terraform output -raw github_actions_service_account_email
```

Add these in GitHub:
`Settings` → `Secrets and variables` → `Actions`

Create these repository secrets:
- `GCP_PROJECT_ID`
- `WIF_PROVIDER`
- `WIF_SERVICE_ACCOUNT`

## Step 11: Test CI/CD

Push a commit to `main` or `develop`.

The workflow at [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml) should:
- run tests
- authenticate to GCP with WIF
- build and push the image
- deploy to Cloud Run on pushes where the workflow conditions match

## Step 12: Remove Temporary Bootstrap IAM

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

## Teardown

To delete the infrastructure created by this repo without deleting the whole
GCP project:

```bash
cd rupert-security-conductor
bash infra/scripts/destroy.sh "$GCP_PROJECT_ID" "$GCP_REGION"
```

The script:
1. runs `terraform destroy`
2. then does best-effort `gcloud` cleanup for the named Cloud Run service,
   Artifact Registry repo, app secrets, service accounts, and GitHub WIF
   resources created by this repo

For non-interactive use:

```bash
bash infra/scripts/destroy.sh "$GCP_PROJECT_ID" "$GCP_REGION" --yes
```

You can recreate everything later with:

```bash
bash infra/scripts/deploy.sh "$GCP_PROJECT_ID" "$GCP_REGION"
```

## Webhooks

Both webhook endpoints return **202 Accepted** immediately and process the scan
in a background task. Use the `scan_id` in the response to find the result in GCS
at `gs://$GCS_BUCKET_NAME/scans/<scan_id>/`.

GitHub:
1. Open your repository settings.
2. Go to `Webhooks`.
3. Add a webhook pointing to:
   `https://<SERVICE_URL>/webhook/github`
4. Set content type to `application/json`.
5. Enter your `GITHUB_WEBHOOK_SECRET` value in the **Secret** field.
6. Select the **Push** event (or "Just the push event").

GitHub will sign every delivery with `X-Hub-Signature-256`. The app verifies
this signature and rejects requests that do not match. The diff is fetched
automatically from the GitHub API — you do **not** need to include `diff_content`
in the payload.

Bitbucket:
1. Open repository settings.
2. Go to `Webhooks`.
3. Add a webhook pointing to:
   `https://<SERVICE_URL>/webhook/bitbucket`
4. Enter your `BITBUCKET_WEBHOOK_SECRET` value in the **Secret** field.
5. Select the **Push** trigger.

Bitbucket will sign every delivery with `X-Hub-Signature`. The app verifies
this signature and rejects requests that do not match.

Note: Bitbucket webhooks do not include a diff. The `diff_content` field must
be provided in the payload by your CI pipeline, or the scan will be skipped.

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
cd infra/terraform
terraform output
```

Destroy managed resources:

```bash
cd infra/terraform
terraform destroy -auto-approve \
  -var="gcp_project_id=$GCP_PROJECT_ID" \
  -var="gcp_region=$GCP_REGION"
```
