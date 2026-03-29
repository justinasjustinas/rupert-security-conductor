"""FastAPI application for GCP Cloud Run deployment."""

import asyncio
import functools
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.agents import (
    run_hunter_agent,
    run_reporter_agent,
    run_verifier_agent,
)
from app.logging_config import LogContext, get_logger, setup_logging
from app.models import (
    HealthResponse,
    ScanRequest,
    ScanResult,
    Severity,
)

# Initialize logging
setup_logging(level=os.getenv("LOG_LEVEL", "INFO"))
logger = get_logger(__name__)

# Maximum number of scans that may run concurrently in this process.
_MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
_scan_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)

# Maximum diff size accepted (default 500 KB). Larger payloads are rejected
# to prevent quota exhaustion and context-window overflow.
_MAX_DIFF_BYTES = int(os.getenv("MAX_DIFF_SIZE_BYTES", str(500 * 1024)))

app = FastAPI(
    title="Rupert Security Conductor",
    description="AI-powered vulnerability scanner using Pydantic-AI agents",
    version="0.1.0",
)


# ============================================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================================


@app.middleware("http")
async def add_security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Add defensive HTTP security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


# ============================================================================
# AUTH HELPERS
# ============================================================================


def _scan_api_token() -> str:
    """Return the configured bearer token for /scan."""
    return os.getenv("SCAN_API_TOKEN", "").strip()


def _verify_scan_authorization(authorization: str | None) -> None:
    """Enforce bearer-token auth on /scan.

    Fails *closed*: if SCAN_API_TOKEN is not configured the endpoint is
    locked unless SCAN_AUTH_DISABLED=true is explicitly set.
    """
    expected_token = _scan_api_token()

    if not expected_token:
        if os.getenv("SCAN_AUTH_DISABLED", "").strip().lower() == "true":
            return
        logger.warning("AUDIT: /scan rejected — SCAN_API_TOKEN not configured")
        raise HTTPException(
            status_code=503,
            detail=(
                "Scan endpoint authentication is not configured. "
                "Set SCAN_API_TOKEN or set SCAN_AUTH_DISABLED=true to "
                "explicitly allow unauthenticated access."
            ),
        )

    if not authorization or not authorization.startswith("Bearer "):
        logger.warning("AUDIT: /scan rejected — missing bearer token")
        raise HTTPException(status_code=401, detail="Missing bearer token")

    provided_token = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(provided_token, expected_token):
        logger.warning("AUDIT: /scan rejected — invalid bearer token")
        raise HTTPException(status_code=401, detail="Invalid bearer token")


# ============================================================================
# WEBHOOK SIGNATURE VERIFICATION
# ============================================================================


def _verify_webhook_signature(
    raw_body: bytes,
    signature_header: str | None,
    secret_env_var: str,
    header_name: str,
) -> None:
    """Verify an HMAC-SHA256 webhook signature.

    Fails closed: if the env var is not set, the webhook is rejected.
    This ensures webhooks can never be processed without a shared secret.
    """
    secret = os.getenv(secret_env_var, "").strip()
    if not secret:
        logger.error(
            "AUDIT: webhook rejected — %s not configured", secret_env_var
        )
        raise HTTPException(
            status_code=500,
            detail=f"Webhook secret ({secret_env_var}) is not configured on this server.",
        )

    if not signature_header:
        logger.warning("AUDIT: webhook rejected — missing %s header", header_name)
        raise HTTPException(
            status_code=401,
            detail=f"Missing {header_name} header.",
        )

    expected = "sha256=" + hmac.new(
        secret.encode(), raw_body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature_header, expected):
        logger.warning("AUDIT: webhook rejected — signature mismatch on %s", header_name)
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")


# ============================================================================
# INPUT VALIDATION
# ============================================================================


def _validate_diff(diff: str) -> None:
    """Reject diffs that exceed the configured size limit."""
    size = len(diff.encode())
    if size > _MAX_DIFF_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Diff size {size} bytes exceeds maximum of {_MAX_DIFF_BYTES} bytes.",
        )


# ============================================================================
# GITHUB DIFF FETCHING
# ============================================================================


async def _fetch_github_diff(repo_full_name: str, commit_sha: str) -> str:
    """Fetch the diff for a commit from the GitHub API.

    Returns the raw unified diff text, or an empty string on failure.
    """
    token = os.getenv("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github.v3.diff"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://api.github.com/repos/{repo_full_name}/commits/{commit_sha}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            return response.text
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "GitHub diff fetch returned HTTP %s for %s@%s",
            exc.response.status_code,
            repo_full_name,
            commit_sha,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("GitHub diff fetch failed: %s", exc)
    return ""


# ============================================================================
# GCS PERSISTENCE
# ============================================================================


def _gcs_bucket_name() -> str:
    return os.getenv("GCS_BUCKET_NAME", "").strip()


def _sync_save_to_gcs(
    scan_id: str, result: ScanResult, report: str, bucket_name: str
) -> str:
    """Write scan result JSON and Markdown report to GCS.

    Returns the GCS URI of the report blob, or an empty string on failure.
    """
    from google.cloud import storage  # pylint: disable=import-outside-toplevel

    client = storage.Client()
    bucket = client.bucket(bucket_name)

    result_blob = bucket.blob(f"scans/{scan_id}/result.json")
    result_blob.upload_from_string(result.model_dump_json(), content_type="application/json")

    report_uri = ""
    if report:
        report_blob = bucket.blob(f"scans/{scan_id}/report.md")
        report_blob.upload_from_string(report, content_type="text/markdown")
        report_uri = f"gs://{bucket_name}/scans/{scan_id}/report.md"

    return report_uri


async def _save_scan_to_gcs(scan_id: str, result: ScanResult, report: str) -> str:
    """Async wrapper around _sync_save_to_gcs. Returns GCS report URI or ''."""
    bucket_name = _gcs_bucket_name()
    if not bucket_name:
        return ""
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(
            None,
            functools.partial(_sync_save_to_gcs, scan_id, result, report, bucket_name),
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("GCS save failed for scan %s: %s", scan_id, exc, exc_info=True)
        return ""


# ============================================================================
# ENDPOINTS
# ============================================================================


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint for Cloud Run."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        timestamp=datetime.utcnow(),
    )


@app.post("/scan", response_model=ScanResult)
async def start_scan(
    request: ScanRequest, authorization: str | None = Header(default=None)
) -> ScanResult:
    """Initiate a security scan with code diff."""
    _verify_scan_authorization(authorization)
    _validate_diff(request.code_diff)

    scan_id = str(uuid.uuid4())
    logger.info(
        "AUDIT: scan_requested",
        extra={
            "scan_id": scan_id,
            "repository": request.repository,
            "commit_hash": request.commit_hash,
            "author": request.author,
            "diff_bytes": len(request.code_diff.encode()),
        },
    )

    try:
        result = await orchestrate_security_scan(
            scan_id=scan_id,
            repository=request.repository,
            commit_hash=request.commit_hash,
            code_diff=request.code_diff,
            author=request.author,
        )
        return result

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Scan failed", extra={"scan_id": scan_id}, exc_info=True)
        raise HTTPException(status_code=500, detail="Scan orchestration failed") from exc


@app.post("/webhook/github")
async def github_webhook(
    request: Request, background_tasks: BackgroundTasks
) -> JSONResponse:
    """GitHub webhook handler for push events.

    Verifies the X-Hub-Signature-256 HMAC header, then returns 202 immediately
    and processes the scan in a background task.
    """
    scan_id = str(uuid.uuid4())

    raw_body = await request.body()
    _verify_webhook_signature(
        raw_body,
        request.headers.get("X-Hub-Signature-256"),
        "GITHUB_WEBHOOK_SECRET",
        "X-Hub-Signature-256",
    )

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in GitHub webhook payload", extra={"scan_id": scan_id})
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    repo_info = payload.get("repository", {})
    logger.info(
        "AUDIT: github_webhook_received",
        extra={"scan_id": scan_id, "repo": repo_info.get("full_name")},
    )

    if not payload.get("ref"):
        logger.info("Skipping non-branch push event", extra={"scan_id": scan_id})
        return JSONResponse({"status": "skipped", "reason": "not_a_branch_push"})

    repo_full_name = repo_info.get("full_name", repo_info.get("name", "unknown"))
    commit_sha = payload.get("after", "")
    author = payload.get("pusher", {}).get("name", "github-webhook")

    diff_content: str = payload.get("diff_content", "")
    if not diff_content and commit_sha:
        diff_content = await _fetch_github_diff(repo_full_name, commit_sha)

    if not diff_content:
        logger.warning("No diff available for scan", extra={"scan_id": scan_id})
        return JSONResponse(
            {"status": "skipped", "scan_id": scan_id, "reason": "no_diff_available"},
            status_code=202,
        )

    try:
        _validate_diff(diff_content)
    except HTTPException:
        logger.warning(
            "AUDIT: webhook diff rejected — size limit exceeded",
            extra={"scan_id": scan_id, "diff_bytes": len(diff_content.encode())},
        )
        raise

    background_tasks.add_task(
        _background_scan_task,
        scan_id=scan_id,
        repository=repo_full_name,
        commit_hash=commit_sha,
        code_diff=diff_content,
        author=author,
    )

    return JSONResponse({"status": "accepted", "scan_id": scan_id}, status_code=202)


@app.post("/webhook/bitbucket")
async def bitbucket_webhook(
    request: Request, background_tasks: BackgroundTasks
) -> JSONResponse:
    """Bitbucket webhook handler for push events.

    Verifies the X-Hub-Signature HMAC header, then returns 202 immediately
    and processes the scan in a background task.
    """
    scan_id = str(uuid.uuid4())

    raw_body = await request.body()
    _verify_webhook_signature(
        raw_body,
        request.headers.get("X-Hub-Signature"),
        "BITBUCKET_WEBHOOK_SECRET",
        "X-Hub-Signature",
    )

    try:
        payload = json.loads(raw_body)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Invalid JSON in Bitbucket webhook payload", extra={"scan_id": scan_id})
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    logger.info("AUDIT: bitbucket_webhook_received", extra={"scan_id": scan_id})

    changes = payload.get("push", {}).get("changes", [])
    if not changes:
        logger.info("Skipping push with no changes", extra={"scan_id": scan_id})
        return JSONResponse({"status": "skipped", "reason": "no_changes"})

    diff_content: str = payload.get("diff_content", "")
    repo_name = payload.get("repository", {}).get("full_name") or payload.get(
        "repository", {}
    ).get("name", "unknown")
    commit_sha = changes[0].get("new", {}).get("hash", "")

    if not diff_content:
        logger.warning("No diff_content in Bitbucket webhook payload", extra={"scan_id": scan_id})
        return JSONResponse(
            {"status": "skipped", "scan_id": scan_id, "reason": "no_diff_available"},
            status_code=202,
        )

    try:
        _validate_diff(diff_content)
    except HTTPException:
        logger.warning(
            "AUDIT: webhook diff rejected — size limit exceeded",
            extra={"scan_id": scan_id, "diff_bytes": len(diff_content.encode())},
        )
        raise

    background_tasks.add_task(
        _background_scan_task,
        scan_id=scan_id,
        repository=repo_name,
        commit_hash=commit_sha,
        code_diff=diff_content,
        author="bitbucket-webhook",
    )

    return JSONResponse({"status": "accepted", "scan_id": scan_id}, status_code=202)


# ============================================================================
# BACKGROUND TASK
# ============================================================================


async def _background_scan_task(
    scan_id: str,
    repository: str,
    commit_hash: str,
    code_diff: str,
    author: str,
) -> None:
    """Run a full security scan in the background and persist the result."""
    try:
        result = await orchestrate_security_scan(
            scan_id=scan_id,
            repository=repository,
            commit_hash=commit_hash,
            code_diff=code_diff,
            author=author,
        )
        if not _gcs_bucket_name():
            logger.warning(
                "GCS_BUCKET_NAME not set — scan result will not be persisted",
                extra={"scan_id": scan_id},
            )
        logger.info(
            "AUDIT: background_scan_completed",
            extra={
                "scan_id": scan_id,
                "repository": repository,
                "commit_hash": commit_hash,
                "author": author,
                "total_findings": result.total_vulnerabilities,
                "critical_count": result.critical_count,
                "high_count": result.high_count,
            },
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Background scan task failed: %s",
            exc,
            extra={"scan_id": scan_id},
            exc_info=True,
        )


# ============================================================================
# ORCHESTRATION LOGIC
# ============================================================================


async def orchestrate_security_scan(
    scan_id: str,
    repository: str,
    commit_hash: str,
    code_diff: str,
    author: str,
) -> ScanResult:
    """Orchestrate the full security scanning workflow.

    Acquires a semaphore slot to cap the number of concurrent LLM-backed
    scans, preventing API quota exhaustion under load.
    """
    async with _scan_semaphore:
        return await _run_scan_pipeline(
            scan_id=scan_id,
            repository=repository,
            commit_hash=commit_hash,
            code_diff=code_diff,
            author=author,
        )


async def _run_scan_pipeline(
    scan_id: str,
    repository: str,
    commit_hash: str,
    code_diff: str,
    author: str,
) -> ScanResult:
    """Internal pipeline: Hunt → Verify → Report → Persist."""
    with LogContext(logger, scan_id):
        logger.info(
            "Starting security orchestration",
            extra={"repository": repository, "author": author},
        )

        # STAGE 1: Hunter Agent - Find vulnerabilities
        logger.info("Stage 1: Running Hunter agent")
        hunter_findings = await run_hunter_agent(code_diff, scan_id)

        # STAGE 2: Verifier Agent - Validate findings
        logger.info("Stage 2: Running Verifier agent")
        verified_findings = await run_verifier_agent(hunter_findings, code_diff, scan_id)

        # STAGE 3: Reporter Agent - Generate Markdown report
        logger.info("Stage 3: Running Reporter agent")
        report = await run_reporter_agent(verified_findings, repository, commit_hash, scan_id)

        # Count findings by severity
        critical = sum(1 for f in verified_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in verified_findings if f.severity == Severity.HIGH)

        summary = (
            f"Found {len(verified_findings)} security issue(s): "
            f"{critical} critical, {high} high"
        )

        logger.info(
            "AUDIT: scan_completed",
            extra={
                "scan_id": scan_id,
                "repository": repository,
                "commit_hash": commit_hash,
                "author": author,
                "total_findings": len(verified_findings),
                "critical": critical,
                "high": high,
            },
        )

        result = ScanResult(
            scan_id=scan_id,
            timestamp=datetime.utcnow(),
            repository=repository,
            commit_hash=commit_hash,
            findings=verified_findings,
            summary=summary,
            total_vulnerabilities=len(verified_findings),
            critical_count=critical,
            high_count=high,
            report=report,
        )

        # STAGE 4: Persist to GCS (non-blocking on failure)
        report_url = await _save_scan_to_gcs(scan_id, result, report)
        if report_url:
            result = result.model_copy(update={"report_url": report_url})
            logger.info("Scan persisted to GCS", extra={"report_url": report_url})

        return result


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
