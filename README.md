# Rupert Security Conductor

AI-powered code-diff security scanning with FastAPI, Pydantic-AI, Google Gemini, and GCP Cloud Run.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full deployment walkthrough.

## What It Does

Rupert scans code diffs in three stages:
- Hunt: identify likely vulnerabilities
- Verify: reduce false positives
- Report: generate a summary of verified findings

Main endpoints:
- `GET /health`
- `POST /scan`
- `POST /webhook/github`
- `POST /webhook/bitbucket`

## Local Development

Requirements:
- Python 3.12+
- Docker
- `gcloud`
- Terraform

Setup:

```bash
cd /Users/yourUsernameHere/Workspace/rupert-security-conductor
bash infra/scripts/setup-dev.sh
source venv/bin/activate
export GEMINI_API_KEY="your-api-key"
uvicorn app.main:app --reload
```

Test:

```bash
curl http://localhost:8000/health
pytest
```

## Deployment Summary

The deployment flow is:
1. Create or choose a GCP project.
2. Enable required GCP APIs.
3. Grant temporary bootstrap IAM to the human account doing the first deploy.
4. Export `GEMINI_API_KEY`, `GITHUB_REPOSITORY_OWNER`, and `GITHUB_REPOSITORY_NAME`.
5. Run `bash infra/scripts/deploy.sh "$GCP_PROJECT_ID" "$GCP_REGION"`.
6. Add the generated WIF values to GitHub Actions secrets.
7. Remove the temporary bootstrap IAM from your human account after CI/CD is working.

That step-by-step version lives in [DEPLOYMENT.md](DEPLOYMENT.md).

## Security Notes

Current infrastructure identity model:
- Cloud Run runtime service account:
  - `artifactregistry.reader`
  - `secretmanager.secretAccessor`
  - `logging.logWriter`
- GitHub Actions deployer:
  - `artifactregistry.writer`
  - `run.admin`
  - `iam.serviceAccountUser` on the runtime service account
  - `iam.workloadIdentityUser` scoped to your GitHub repository

Important: the app itself still needs hardening around public access and webhook signature verification. The deployment docs only cover infrastructure setup.

## Useful Commands

Get the service URL:

```bash
gcloud run services describe rupert-security-conductor \
  --region=europe-west1 \
  --format='value(status.url)'
```

Read logs:

```bash
gcloud logging read "resource.labels.service_name=rupert-security-conductor" \
  --limit 20 \
  --format "table(timestamp,severity,jsonPayload.message)"
```

Destroy managed resources:

```bash
cd /Users/yourUsernameHere/Workspace/rupert-security-conductor/infra/terraform
terraform destroy -auto-approve \
  -var="gcp_project_id=$GCP_PROJECT_ID" \
  -var="gcp_region=$GCP_REGION"
```
