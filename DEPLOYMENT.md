# Rupert Security Conductor - Step-by-Step Deployment Guide

## Prerequisites Checklist

- [ ] gcloud CLI installed and authenticated
- [ ] Terraform installed (v1.0+)
- [ ] Docker installed
- [ ] GCP account with billing enabled
- [ ] Python 3.12+ installed
- [ ] Gemini API key obtained

## Step 1: Create GCP Project

### Option A: Using Console

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Click "Create Project"
3. Name: `Rupert Security Conductor`
4. Click "Create"

### Option B: Using gcloud CLI

```bash
gcloud projects create rupert-security-conductor --display-name="Rupert Security Conductor"
gcloud config set project rupert-security-conductor
```

## Step 2: Enable Required APIs

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  logging.googleapis.com
```

## Step 3: Get Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Click "Create API Key"
3. Copy the API key
4. Save to a secure location

**Optional**: Store in shell variable:
```bash
export GEMINI_API_KEY="your-api-key-here"
```

## Step 4: Setup Local Development (Optional)

```bash
cd rupert-security-conductor
bash infra/scripts/setup-dev.sh

# Activate venv
source venv/bin/activate

# Create .env file with your API key
echo "GEMINI_API_KEY=$GEMINI_API_KEY" > .env

# Run locally
uvicorn app.main:app --reload
```

Test the API:
```bash
curl http://localhost:8000/health
```

## Step 5: Deploy to GCP Cloud Run

```bash
# Set project ID
export GCP_PROJECT_ID="rupert-security-conductor"
export GCP_REGION="eu-west1"

# Run deployment (builds Docker image, pushes to AR, deploys to Cloud Run)
bash infra/scripts/deploy.sh $GCP_PROJECT_ID $GCP_REGION
```

## Step 6: Add Gemini API Key to Secrets Manager

**After terraform deployment completes:**

```bash
gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"
```

Verify it was added:
```bash
gcloud secrets versions list rupert-gemini-api-key
```

## Step 7: Test the Deployment

```bash
# Get the Cloud Run URL
SERVICE_URL=$(gcloud run services describe rupert-security-conductor \
  --region=$GCP_REGION \
  --format='value(status.url)')

echo $SERVICE_URL

# Test health endpoint
curl $SERVICE_URL/health

# Test scan endpoint
curl -X POST $SERVICE_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "test-repo",
    "branch": "main",
    "commit_hash": "abc123",
    "code_diff": "- const sql = \"SELECT * FROM users WHERE id = \" + userId;",
    "author": "test@example.com"
  }'
```

## Step 8: Setup Webhooks (Optional)

### GitHub Webhook

1. Go to your GitHub repository
2. Settings → Webhooks → Add webhook
3. Payload URL: `https://<SERVICE_URL>/webhook/github`
4. Content type: `application/json`
5. Events: `push`, `pull_request`
6. Create webhook

### Bitbucket Webhook

1. Go to your Bitbucket repository
2. Settings → Webhooks → Create webhook
3. URL: `https://<SERVICE_URL>/webhook/bitbucket`
4. Events: `Repository push`
5. Create webhook

## Step 9: Monitor Logs

```bash
# View recent logs
gcloud logging read "resource.labels.service_name=rupert-security-conductor" \
  --limit 50 \
  --format "table(timestamp,severity,jsonPayload.message)"

# Watch logs in real-time
gcloud logging read "resource.labels.service_name=rupert-security-conductor" \
  --limit 20 \
  --format "table(timestamp,severity,jsonPayload.message)" \
  --follow

# Find logs by scan_id
SCAN_ID="your-scan-id-here"
gcloud logging read "jsonPayload.scan_id=$SCAN_ID" --format json
```

## Step 10 (Optional): Setup CI/CD with GitHub Actions

1. Go to GitHub repository Settings → Secrets and variables → Actions
2. Add the following secrets:
   - `GCP_PROJECT_ID`: Your GCP project ID
   - `WIF_PROVIDER`: Workload Identity Federation provider (for auth)
   - `WIF_SERVICE_ACCOUNT`: Service account for CI/CD

3. Create `.github/workflows/ci-cd.yml` (already in the repo)
4. On every push to main, the pipeline will:
   - Run tests
   - Build Docker image
   - Push to Artifact Registry
   - Deploy to Cloud Run

## Troubleshooting

### Secret not found
```bash
# List existing secrets
gcloud secrets list

# Create if missing
gcloud secrets create rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"
```

### Cloud Run service fails on startup
```bash
# Check detailed logs
gcloud logging read "resource.labels.service_name=rupert-security-conductor" \
  --limit 10 \
  --format="table(timestamp,severity,textPayload)"

# Redeploy
bash infra/scripts/deploy.sh $GCP_PROJECT_ID $GCP_REGION
```

### Docker build issues
```bash
# Clear Docker cache
docker system prune -a

# Rebuild
docker build --no-cache -t test:latest .
```

### Terraform state issues
```bash
# If using local state, validate
cd infra/terraform
terraform validate
terraform plan

# Remote state requires gs:// bucket (commented in main.tf)
```

## Cleanup

To delete all resources and avoid charges:

```bash
cd infra/terraform
terraform destroy -auto-approve \
  -var="gcp_project_id=$GCP_PROJECT_ID" \
  -var="gcp_region=$GCP_REGION"

# Optional: Delete entire GCP project
gcloud projects delete $GCP_PROJECT_ID
```

## Cost Summary

With this setup:
- Cloud Run: Free (180k vCPU-sec/month free tier)
- Gemini API: ~$0-5/month (free tier available for testing)
- Artifact Registry: Free (first 500GB)
- Cloud Logging: Free (first 50GB/month)
- Secret Manager: Free (6 free secrets)

**Expected Total**: $0-5/month on free tier

---

For problems or questions, check the README.md or run:
```bash
make help
```
