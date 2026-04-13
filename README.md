# Rupert Security Conductor

AI-powered code-diff security scanning with FastAPI, Pydantic-AI, Google Gemini, and GCP Cloud Run.
It's just an experiment in multi-agent pipelines where one stage adversarially challenges the previous one's output — applied to code diff security scanning."

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
cd rupert-security-conductor
bash infra/scripts/setup-dev.sh
source .venv/bin/activate
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

## Data Privacy

**Code diffs submitted to this service are sent to Google's Gemini API.**

This includes all content present in the diff — source code, comments, string literals, and any secrets or credentials that may have been accidentally committed. Before deploying or using this service you must ensure:

- You are authorised to share the code with Google (review Google's [Gemini API Terms of Service](https://ai.google.dev/terms) and your organisation's data classification policy).
- Diffs submitted do not contain credentials, API keys, or other secrets. Consider running a secret-scanning step (e.g. `truffleHog`, `git-secrets`) before submitting to this service.
- Your users are informed that their code will be processed by an external AI service.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Gemini API key for the LLM agents |
| `SCAN_API_TOKEN` | **Required in production** | Bearer token required on `POST /scan`. If unset, the endpoint returns 503 unless `SCAN_AUTH_DISABLED=true` is also set. |
| `SCAN_AUTH_DISABLED` | No | Set to `true` only for local dev to explicitly allow unauthenticated `/scan` access. Never set in production. |
| `GITHUB_WEBHOOK_SECRET` | **Required** | Shared secret used to verify `X-Hub-Signature-256` on GitHub webhooks. Webhooks are rejected if this is not set. |
| `BITBUCKET_WEBHOOK_SECRET` | **Required** | Shared secret used to verify `X-Hub-Signature` on Bitbucket webhooks. Webhooks are rejected if this is not set. |
| `GITHUB_TOKEN` | Recommended | GitHub personal access token (`repo` read scope) for fetching diffs. Without it, public-repo diffs still work but rate limits are tighter; private repos will not work at all. |
| `GCS_BUCKET_NAME` | Recommended | GCS bucket where scan results (`result.json`) and Markdown reports (`report.md`) are persisted under `scans/{scan_id}/`. |
| `MAX_CONCURRENT_SCANS` | No | Maximum scans running simultaneously in this process (default: `5`). |
| `MAX_DIFF_SIZE_BYTES` | No | Maximum diff size accepted in bytes (default: `512000` = 500 KB). Larger requests are rejected with HTTP 413. |
| `LOG_LEVEL` | No | Python logging level (default: `INFO`) |
| `GCP_PROJECT_ID` | Deployment | GCP project used during deployment |
| `GCP_REGION` | Deployment | GCP region (default in scripts: `europe-west1`) |

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

## Webhook Behaviour

Both `/webhook/github` and `/webhook/bitbucket` return **202 Accepted** immediately and process the scan in a background task. For the GitHub webhook, the app automatically fetches the diff from the GitHub API using `GITHUB_TOKEN`. Results are persisted to GCS if `GCS_BUCKET_NAME` is set — use the `scan_id` returned in the 202 response to locate them at `gs://$GCS_BUCKET_NAME/scans/{scan_id}/`.

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
cd rupert-security-conductor/infra/terraform
terraform destroy -auto-approve \
  -var="gcp_project_id=$GCP_PROJECT_ID" \
  -var="gcp_region=$GCP_REGION"
```
