# Rupert Security Conductor 🔐

An AI-powered vulnerability scanner orchestrated with Pydantic-AI agents, deployed to GCP Cloud Run on the free tier.

## 🎯 Overview

Rupert Security Conductor is a hobby-tier security scanner that uses AI agents to:

1. **Hunt** - Scan code diffs for OWASP vulnerabilities and logic flaws
2. **Verify** - Use adversarial reasoning to confirm findings (reduce false positives)
3. **Report** - Generate actionable Markdown security reports for GitHub/Bitbucket

The system is designed for minimal cost ($0/month) using:
- **GCP Cloud Run** (free tier: 180k vCPU-seconds/month)
- **Google Gemini 1.5 Flash** (free tier API available)
- **Google Cloud Logging** (free tier: 50GB/month ingestion)
- **Artifact Registry** (free tier storage)

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub/Bitbucket Webhooks               │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Cloud Run Service                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Endpoints:                                             │ │
│  │ • POST /scan          - Manual scan trigger            │ │
│  │ • POST /webhook/github - GitHub webhook handler       │ │
│  │ • POST /webhook/bitbucket - Bitbucket webhook handler │ │
│  │ • GET /health         - Health check                   │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
   ┌──────────────┐  ┌──────────────┐  ┌────────────────┐
   │ Hunter Agent │  │Verifier Agent│  │ Reporter Agent │
   │ (Finds vulns)│  │(Validates)   │  │(Formats)       │
   └──────────────┘  └──────────────┘  └────────────────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         │                                   │
         ▼                                   ▼
   Google Gemini              GCP Cloud Logging
   1.5 Flash API              (JSON Logs + scan_id)
```

### Agent Workflow

1. **Hunter Agent** - Analyzes code diffs using Gemini
   - Identifies OWASP Top 10 vulnerabilities
   - Detects logic flaws
   - Returns structured findings

2. **Verifier Agent** - Adversarial validation
   - Attempts to "prove" each finding exists
   - Evaluates exploitability
   - Reduces false positives
   - Returns verdict: CONFIRMED | REFUTED | UNCERTAIN

3. **Reporter Agent** - Markdown report generation
   - Aggregates verified findings
   - Groups by severity (CRITICAL → INFO)
   - Generates remediation recommendations
   - Formats for GitHub issue/PR comments

All operations are traced through Cloud Logging with shared `scan_id` for audit trail.

## 📁 Project Structure

```
rupert-security-conductor/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── agents.py            # Pydantic-AI agent definitions
│   ├── models.py            # Pydantic schemas
│   └── logging_config.py    # Structured JSON logging
├── infra/
│   ├── terraform/
│   │   ├── main.tf          # Cloud Run, Artifact Registry, IAM, Secrets
│   │   ├── variables.tf     # Variable definitions
│   │   └── outputs.tf       # Terraform outputs
│   └── scripts/
│       ├── deploy.sh        # One-command deployment
│       └── setup-dev.sh     # Local development setup
├── Dockerfile               # Python 3.12 slim image
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── .gitignore
└── .dockerignore
```

## 🚀 Quick Start

### Prerequisites

- **gcloud CLI** - [Install](https://cloud.google.com/sdk/docs/install)
- **Terraform** - [Install](https://www.terraform.io/downloads)
- **Docker** - [Install](https://docs.docker.com/get-docker/)
- **Python 3.12+** (for local development)
- **GCP Project** with billing enabled (though this uses free tier)

### 1️⃣ Local Development Setup

```bash
# Clone and setup
cd rupert-security-conductor
bash infra/scripts/setup-dev.sh

# Activate virtual environment
source venv/bin/activate

# Run locally
uvicorn app.main:app --reload

# Test
curl http://localhost:8000/health
```

### 2️⃣ Deploy to GCP Cloud Run

#### Step 1: Get Gemini API Key

1. **Create GCP Project**
   ```bash
   gcloud projects create rupert-security --display-name="Rupert Security Conductor"
   gcloud config set project rupert-security
   ```

2. **Enable Required APIs**
   ```bash
   gcloud services enable \
     run.googleapis.com \
     artifactregistry.googleapis.com \
     secretmanager.googleapis.com \
     cloudbuild.googleapis.com \
     logging.googleapis.com
   ```

3. **Get Gemini API Key**
   - Go to [Google AI Studio](https://aistudio.google.com/app/apikey)
   - Create new API key
   - Copy the key

#### Step 2: Terraform Deployment

```bash
# Configure your project ID
export GCP_PROJECT_ID=your-project-id
export GCP_REGION=eu-west1
export GEMINI_API_KEY=your-api-key

# Run deployment script
bash infra/scripts/deploy.sh $GCP_PROJECT_ID $GCP_REGION

# Add Gemini API key to Secrets Manager
gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"
```

The deployment script will:
1. ✅ Build Docker image
2. ✅ Push to Artifact Registry
3. ✅ Create Cloud Run service
4. ✅ Setup IAM permissions
5. ✅ Configure Secrets Manager

#### Step 3: Verify Deployment

```bash
# Get the service URL
gcloud run services describe rupert-security-conductor --region=$GCP_REGION --format='value(status.url)'

# Test health endpoint
curl https://your-cloud-run-url/health

# Trigger a test scan
curl -X POST https://your-cloud-run-url/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "test-repo",
    "branch": "main",
    "commit_hash": "abc123",
    "code_diff": "- const sql = \"SELECT * FROM users WHERE id = \" + userId;\n+ const stmt = db.prepare(\"SELECT * FROM users WHERE id = ?\");\n  stmt.run(userId);"
  }'
```

### 3️⃣ Configure Webhooks

#### GitHub

1. Go to repository Settings → Webhooks → Add webhook
2. **Payload URL**: `https://your-cloud-run-url/webhook/github`
3. **Content type**: `application/json`
4. **Events**: `push`, `pull_request`
5. Create webhook

#### Bitbucket

1. Go to repository Settings → Webhooks → Create webhook
2. **URL**: `https://your-cloud-run-url/webhook/bitbucket`
3. **Events**: `Repository push`
4. Create webhook

## 📊 API Endpoints

### Health Check
```bash
GET /health
```
Returns service status and version.

### Manual Scan
```bash
POST /scan
Content-Type: application/json

{
  "repository": "my-repo",
  "branch": "main",
  "commit_hash": "abc123...",
  "code_diff": "diff content here...",
  "author": "developer@example.com"
}
```

Returns:
```json
{
  "scan_id": "uuid-string",
  "timestamp": "2026-03-12T10:30:45Z",
  "repository": "my-repo",
  "commit_hash": "abc123...",
  "findings": [
    {
      "vulnerability_type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "file_path": "query.py",
      "line_number": 42,
      "description": "Unsanitized SQL query concatenation",
      "evidence": "sql = 'SELECT * FROM users WHERE id = ' + user_id",
      "remediation": "Use parameterized queries with prepared statements",
      "verified": true
    }
  ],
  "summary": "Found 3 security issue(s): 1 critical, 2 high",
  "total_vulnerabilities": 3,
  "critical_count": 1,
  "high_count": 2
}
```

### GitHub Webhook
```bash
POST /webhook/github
```
Automatically triggered on push events.

### Bitbucket Webhook
```bash
POST /webhook/bitbucket
```
Automatically triggered on push events.

## 🔐 Security Configuration

### IAM Service Account

The Cloud Run service uses a minimal-permission service account with:
- ✅ `artifactregistry.reader` - Pull Docker images
- ✅ `secretmanager.secretAccessor` - Read Gemini API key
- ✅ `logging.logWriter` - Write structured logs
- ❌ No Cloud Storage access
- ❌ No Compute access
- ❌ No other GCP service access

### Secrets Management

API key stored in Google Secret Manager:
```bash
# Retrieve for local use (if needed)
gcloud secrets versions access latest --secret="rupert-gemini-api-key"

# Rotate API key
gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< "$NEW_API_KEY"
```

## 📝 Structured Logging

All logs follow GCP Cloud Logging standards with JSON structure:

```json
{
  "timestamp": "2026-03-12T10:30:45.123456Z",
  "severity": "INFO",
  "message": "Hunter found 3 potential vulnerabilities",
  "logger": "app.agents",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "source": {
    "file": "agents.py",
    "function": "run_hunter_agent",
    "line": 142
  },
  "finding_count": 3
}
```

Access logs in Cloud Console:
```bash
gcloud logging read "resource.type=cloud_run_managed_environment AND severity=ERROR" \
  --limit 50 \
  --format json
```

## 🚨 Monitoring and Debugging

### View Cloud Run Logs
```bash
gcloud logging read \
  "resource.labels.service_name=rupert-security-conductor" \
  --limit 50 \
  --format "table(timestamp,severity,jsonPayload.message)"
```

### Check Cloud Run Service Status
```bash
gcloud run services describe rupert-security-conductor --region=$GCP_REGION
```

### View Recent Scans (by scan_id)
```bash
SCAN_ID="your-scan-id"
gcloud logging read "jsonPayload.scan_id=$SCAN_ID" --format json
```

## 💰 Cost Breakdown (Free Tier)

| Service | Quota | Cost |
|---------|-------|------|
| Cloud Run | 180,000 vCPU-seconds/month | $0 |
| Gemini 1.5 Flash | API free tier available | $0* |
| Artifact Registry | 500GB storage | $0 (first 500GB) |
| Cloud Logging | 50GB ingestion/month | $0 (first 50GB) |
| Secret Manager | 6 secrets free | $0 |
| **Total** | | **$0/month** |

*Gemini API pricing: $0.075/1M input tokens, $0.30/1M output tokens (free tier available; estimate ~$0-5/month for 100 scans)

## 🔧 Development

### Adding Custom Agents

1. Create new agent in `app/agents.py`:
```python
my_agent = Agent(
    model="gemini-1.5-flash",
    name="MyAgent",
    system_prompt="..."
)

async def run_my_agent(...) -> ...:
    result = await my_agent.run(...)
    return ...
```

2. Integrate into orchestration in `app/main.py`:
```python
async def orchestrate_security_scan(...):
    ...
    my_result = await run_my_agent(...)
    ...
```

### Running Tests Locally

```bash
pip install pytest pytest-asyncio httpx
python -m pytest

# With coverage
pytest --cov=app
```

## 📚 Dependencies

- **FastAPI** - Web framework
- **Uvicorn** - ASGI server
- **Pydantic-AI** - Agent orchestration framework
- **Google Cloud Client Libraries** - GCP integration
- **python-dotenv** - Environment configuration

## 🐛 Troubleshooting

### "Secret not found" error
```bash
# Create the secret
gcloud secrets create rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"

# Or add new version
gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"
```

### Cloud Run service fails to start
```bash
# Check logs
gcloud logging read "resource.labels.service_name=rupert-security-conductor" --limit 20

# Re-deploy
bash infra/scripts/deploy.sh $GCP_PROJECT_ID $GCP_REGION
```

### Docker build fails
```bash
# Clear cache and rebuild
docker build --no-cache -t test:latest .
```

## 🔄 Cleanup

To delete all GCP resources:

```bash
cd infra/terraform
terraform destroy -auto-approve \
  -var="gcp_project_id=$GCP_PROJECT_ID" \
  -var="gcp_region=$GCP_REGION"
```

To delete the entire GCP project:
```bash
gcloud projects delete $GCP_PROJECT_ID
```

## 📖 Additional Resources

- [Pydantic-AI Documentation](https://ai.pydantic.dev/)
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Google Cloud Run](https://cloud.google.com/run/docs)
- [Google Gemini API](https://ai.google.dev/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## 📄 License

MIT

---

**Built with ❤️ for the security-conscious developer.**
