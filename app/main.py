"""FastAPI application for GCP Cloud Run deployment."""

import json
import os
import uuid
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
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

app = FastAPI(
    title="Rupert Security Conductor",
    description="AI-powered vulnerability scanner using Pydantic-AI agents",
    version="0.1.0",
)


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
async def start_scan(request: ScanRequest) -> ScanResult:
    """Initiate a security scan with code diff."""
    scan_id = str(uuid.uuid4())
    logger.info(
        "Scan initiated",
        extra={"scan_id": scan_id, "repository": request.repository},
    )

    try:
        # Run the security orchestration with structured logging
        result = await orchestrate_security_scan(
            scan_id=scan_id,
            repository=request.repository,
            commit_hash=request.commit_hash,
            code_diff=request.code_diff,
            author=request.author,
        )
        return result

    except Exception as e:
        logger.error(
            f"Scan failed: {str(e)}",
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"Scan orchestration failed: {str(e)}",
        )


@app.post("/webhook/github")
async def github_webhook(request: Request) -> JSONResponse:
    """GitHub webhook handler for push events."""
    scan_id = str(uuid.uuid4())

    try:
        payload = await request.json()
        logger.info(
            "GitHub webhook received",
            extra={
                "scan_id": scan_id,
                "repo": payload.get("repository", {}).get("name"),
            },
        )

        # Extract relevant data from GitHub webhook
        if not payload.get("ref"):
            logger.info("Skipping non-branch push event", extra={"scan_id": scan_id})
            return JSONResponse({"status": "skipped", "reason": "not_a_branch_push"})

        # For MVP, we'd need to fetch the diff from GitHub using their API
        # For now, require diff_content in payload or use empty string
        diff_content = payload.get("diff_content", "")

        if not diff_content:
            logger.warning(
                "No diff_content in webhook payload",
                extra={"scan_id": scan_id},
            )
            return JSONResponse(
                {
                    "status": "queued",
                    "scan_id": scan_id,
                    "message": "Diff fetching not implemented",
                },
                status_code=202,
            )

        repo_name = payload.get("repository", {}).get("name", "unknown")
        commit_sha = payload.get("after", "")

        # Run scan asynchronously (in production, queue to Pub/Sub)
        result = await orchestrate_security_scan(
            scan_id=scan_id,
            repository=repo_name,
            commit_hash=commit_sha,
            code_diff=diff_content,
            author=payload.get("pusher", {}).get("name", "github-webhook"),
        )

        return JSONResponse(
            {
                "status": "completed",
                "scan_id": scan_id,
                "findings_count": len(result.findings),
                "critical_count": result.critical_count,
            },
            status_code=202,
        )

    except json.JSONDecodeError:
        logger.error("Invalid JSON in webhook payload", extra={"scan_id": scan_id})
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        logger.error(
            f"Webhook processing failed: {str(e)}",
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@app.post("/webhook/bitbucket")
async def bitbucket_webhook(request: Request) -> JSONResponse:
    """Bitbucket webhook handler for push events."""
    scan_id = str(uuid.uuid4())

    try:
        payload = await request.json()
        logger.info(
            "Bitbucket webhook received",
            extra={"scan_id": scan_id},
        )

        # Bitbucket webhook structure differs from GitHub
        changes = payload.get("push", {}).get("changes", [])
        if not changes:
            logger.info("Skipping push with no changes", extra={"scan_id": scan_id})
            return JSONResponse({"status": "skipped", "reason": "no_changes"})

        # For MVP, simplified handling
        diff_content = payload.get("diff_content", "")

        if not diff_content:
            logger.warning(
                "No diff_content in webhook payload",
                extra={"scan_id": scan_id},
            )
            return JSONResponse(
                {"status": "queued", "scan_id": scan_id},
                status_code=202,
            )

        repo_name = payload.get("repository", {}).get("name", "unknown")
        commit_sha = changes[0].get("new", {}).get("hash", "")

        result = await orchestrate_security_scan(
            scan_id=scan_id,
            repository=repo_name,
            commit_hash=commit_sha,
            code_diff=diff_content,
            author="bitbucket-webhook",
        )

        return JSONResponse(
            {
                "status": "completed",
                "scan_id": scan_id,
                "findings_count": len(result.findings),
            },
            status_code=202,
        )

    except Exception as e:
        logger.error(
            f"Bitbucket webhook failed: {str(e)}",
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Webhook processing failed")


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
    """Orchestrate the full security scanning workflow."""
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
        verified_findings = await run_verifier_agent(
            hunter_findings, code_diff, scan_id
        )

        # STAGE 3: Reporter Agent - Generate Markdown report
        logger.info("Stage 3: Running Reporter agent")
        await run_reporter_agent(verified_findings, repository, commit_hash, scan_id)

        # Count findings by severity
        critical = sum(1 for f in verified_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in verified_findings if f.severity == Severity.HIGH)

        # Generate summary
        summary = f"Found {len(verified_findings)} security issue(s): {critical} critical, {high} high"

        logger.info(
            "Security orchestration complete",
            extra={
                "total_findings": len(verified_findings),
                "critical": critical,
                "high": high,
            },
        )

        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.utcnow(),
            repository=repository,
            commit_hash=commit_hash,
            findings=verified_findings,
            summary=summary,
            total_vulnerabilities=len(verified_findings),
            critical_count=critical,
            high_count=high,
        )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
