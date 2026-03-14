"""Pydantic-AI agent definitions for security orchestration."""

import asyncio
import json
import os
from functools import wraps
from typing import Any, Callable, TypeVar

from pydantic_ai import Agent, RunContext

from app.logging_config import get_logger
from app.models import (
    Finding,
    PotentialFinding,
    Severity,
    VerifiedResult,
    VulnerabilityType,
)

# Strip whitespace from Gemini API key to prevent header errors
gemini_api_key = os.environ.get("GEMINI_API_KEY")
if gemini_api_key:
    os.environ["GEMINI_API_KEY"] = gemini_api_key.strip()

logger = get_logger(__name__)

MODEL_NAME = "google-gla:gemini-1.5-flash"

# ============================================================================
# RETRY DECORATOR: Exponential backoff for LLM calls
# ============================================================================

F = TypeVar("F", bound=Callable[..., Any])


def retry_on_llm_error(
    max_retries: int = 3, base_delay: float = 1.0
) -> Callable[[F], F]:
    """Retry decorator for LLM calls with exponential backoff."""

    def decorator(func: F) -> F:
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Exception | RuntimeError = RuntimeError("No attempts made")
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    last_exception = exc
                    if attempt < max_retries - 1:
                        delay = base_delay * (2**attempt)
                        logger.warning(
                            "LLM call failed, retrying in %ss (attempt %s/%s)",
                            delay,
                            attempt + 1,
                            max_retries,
                            extra={
                                "error": str(exc),
                                "retry_attempt": attempt + 1,
                            },
                        )
                        await asyncio.sleep(delay)
            raise last_exception

        return async_wrapper  # type: ignore

    return decorator


# ============================================================================
# HUNTER AGENT: Scans code diffs for OWASP vulnerabilities
# ============================================================================

def _build_hunter_agent() -> Agent:
    """Create the hunter agent on demand to avoid import-time provider setup."""
    agent = Agent(
        model=MODEL_NAME,
        name="SecurityHunter",
        system_prompt=(
            "You are a security vulnerability hunter scanning code diffs for "
            "OWASP vulnerabilities.\n\n"
            "Analyze the provided code diff and identify:\n"
            "1. SQL Injection vulnerabilities\n"
            "2. Cross-Site Scripting (XSS) vulnerabilities\n"
            "3. Authentication/Authorization bypasses\n"
            "4. Insecure data transmission\n"
            "5. Broken cryptography\n"
            "6. Logic flaws\n"
            "7. Other injection attacks\n\n"
            "For each vulnerability found, provide:\n"
            "- Type (from OWASP Top 10)\n"
            "- Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)\n"
            "- File path and approximate line number\n"
            "- Clear description of the vulnerability\n"
            "- Evidence from the code\n"
            "- Recommended remediation\n\n"
            "Return a JSON array of findings. If no vulnerabilities found, "
            "return empty array []."
        ),
    )

    @agent.tool
    def analyze_code_diff(_ctx: RunContext, diff_content: str) -> str:
        """Analyze a code diff for vulnerabilities."""
        logger.info(
            "hunter_agent analyzing code diff", extra={"diff_size": len(diff_content)}
        )
        return f"Analyzing code diff:\n{diff_content[:500]}..."

    return agent


# ============================================================================
# VERIFIER AGENT: Adversarial agent that proves/disproves vulnerabilities
# ============================================================================

def _build_verifier_agent() -> Agent:
    """Create the verifier agent on demand to avoid import-time provider setup."""
    agent = Agent(
        model=MODEL_NAME,
        name="SecurityVerifier",
        system_prompt=(
            "You are an adversarial security verifier. Your role is to "
            "validate findings from the Hunter agent.\n\n"
            "For each potential vulnerability provided, determine:\n"
            "1. Is this a real vulnerability or a false positive?\n"
            "2. Can an attacker realistically exploit this?\n"
            "3. Are there mitigating factors in the codebase?\n"
            "4. What's the actual risk if exploited?\n\n"
            "Reason through each finding systematically. Use logical "
            "deduction to either:\n"
            "- CONFIRM: This is a legitimate vulnerability\n"
            "- REFUTE: This is a false positive or not exploitable\n"
            "- UNCERTAIN: Need more context\n\n"
            "Provide your verdict and reasoning in JSON format with fields:\n"
            "- finding_id: reference to original finding\n"
            "- verdict: CONFIRMED | REFUTED | UNCERTAIN\n"
            "- explanation: detailed reasoning\n"
            "- confidence: 0-100 (confidence in your verdict)"
        ),
    )

    @agent.tool
    def validate_finding(
        _ctx: RunContext, _finding_json: str, code_context: str
    ) -> str:
        """Validate a specific finding against code context."""
        logger.info("verifier_agent validating finding")
        return f"Validating finding with code context: {code_context[:300]}..."

    return agent


# ============================================================================
# REPORTER AGENT: Aggregates findings into Markdown summary
# ============================================================================

def _build_reporter_agent() -> Agent:
    """Create the reporter agent on demand to avoid import-time provider setup."""
    agent = Agent(
        model=MODEL_NAME,
        name="SecurityReporter",
        system_prompt=(
            "You are a security report generator. Your role is to aggregate "
            "verified findings and create clear, actionable Markdown reports "
            "for GitHub.\n\n"
            "Given a list of verified vulnerabilities, generate a "
            "professional Markdown summary that includes:\n"
            "1. Executive Summary (severity counts, risk level)\n"
            "2. Detailed Findings (grouped by severity)\n"
            "3. Remediation Recommendations (prioritized)\n"
            "4. Scan Metadata (timestamp, commit hash, etc.)\n\n"
            "Format the output as valid Markdown suitable for GitHub PR "
            "comments or issues.\n"
            "Use tables for findings and code blocks for examples."
        ),
    )

    @agent.tool
    def format_findings(_ctx: RunContext, findings_json: str, repo_name: str) -> str:
        """Format findings into Markdown report."""
        logger.info(
            "reporter_agent formatting findings", extra={"repo_name": repo_name}
        )
        return f"Formatting {len(findings_json)} findings for repository {repo_name}..."

    return agent


def _google_api_key_configured() -> bool:
    """Return whether model-backed scanning can run in this process."""
    return bool(os.environ.get("GOOGLE_API_KEY"))


def _result_text(result: Any) -> str:
    """Extract model text from a pydantic-ai run result without depending on stubs."""
    data = getattr(result, "data", result)
    return str(data)


# ============================================================================
# PARSING HELPERS (with graceful fallbacks)
# ============================================================================


def _parse_hunter_findings(response_text: str) -> list[PotentialFinding]:
    """Parse Hunter agent response into PotentialFinding objects."""
    findings = []

    try:
        # Try to extract JSON from response
        response_text = str(response_text).strip()
        if response_text.startswith("["):
            findings_data = json.loads(response_text)
        else:
            # Try to extract JSON from markdown code block
            if "```json" in response_text or "```" in response_text:
                start = response_text.find("[")
                end = response_text.rfind("]") + 1
                if start != -1 and end > start:
                    findings_data = json.loads(response_text[start:end])
                else:
                    findings_data = []
            else:
                findings_data = []

        for item in findings_data or []:
            try:
                findings.append(
                    PotentialFinding(
                        vulnerability_type=VulnerabilityType(
                            item.get("vulnerability_type", "OTHER")
                        ),
                        severity=Severity(item.get("severity", "LOW")),
                        file_path=item.get("file_path", "unknown"),
                        line_number=item.get("line_number", 0),
                        description=item.get("description", ""),
                        evidence=item.get("evidence", ""),
                        remediation=item.get("remediation", ""),
                    )
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.warning("Failed to parse finding: %s", exc)
                continue

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse hunter findings: %s", exc)

    return findings


def _parse_verifier_verdict(response_text: str) -> dict:
    """Parse Verifier agent response."""
    verdict = {"verdict": "UNCERTAIN", "confidence": 50, "explanation": ""}

    try:
        response_text = str(response_text).strip()
        if "{" in response_text:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start != -1:
                verdict = json.loads(response_text[start:end])
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse verifier verdict: %s", exc)

    return verdict


# ============================================================================
# ORCHESTRATION FUNCTIONS
# ============================================================================


@retry_on_llm_error(max_retries=3)
async def run_hunter_agent(diff_content: str, scan_id: str) -> list[PotentialFinding]:
    """Execute Hunter agent to find vulnerabilities.

    Returns:
        List[PotentialFinding]: Unverified findings from Hunter.
    """
    logger.info("Starting hunter agent scan", extra={"scan_id": scan_id})

    if not _google_api_key_configured():
        logger.warning(
            "Skipping hunter agent: GOOGLE_API_KEY is not configured",
            extra={"scan_id": scan_id},
        )
        return []

    try:
        # Run hunter agent with diff content
        result = await _build_hunter_agent().run(
            f"Scan this code diff for vulnerabilities:\n\n{diff_content}",
        )

        # Parse findings from response
        findings = _parse_hunter_findings(_result_text(result))
        logger.info(
            "Hunter found %s potential vulnerabilities",
            len(findings),
            extra={"scan_id": scan_id, "finding_count": len(findings)},
        )
        return findings

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Hunter agent failed: %s",
            exc,
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        return []


@retry_on_llm_error(max_retries=3)
async def run_verifier_agent(
    findings: list[PotentialFinding], diff_content: str, scan_id: str
) -> list[Finding]:
    """Execute Verifier agent to validate findings in parallel.

    Args:
        findings: List of unverified PotentialFinding objects from Hunter.
        diff_content: Original code diff for context.
        scan_id: Trace ID for logging.

    Returns:
        List[Finding]: Only CONFIRMED findings, converted to verified Finding objects.
    """
    logger.info(
        "Starting verifier agent validation",
        extra={"scan_id": scan_id, "finding_count": len(findings)},
    )

    if not findings:
        return []

    try:
        # Process all findings in parallel
        verification_tasks = [
            _verify_single_finding(finding, diff_content, scan_id)
            for finding in findings
        ]
        verified_results = await asyncio.gather(
            *verification_tasks, return_exceptions=True
        )

        # Filter for CONFIRMED findings and convert to Finding objects
        confirmed_findings = []
        for result in verified_results:
            if isinstance(result, Exception):
                logger.warning(
                    "Verification task failed: %s",
                    result,
                    extra={"scan_id": scan_id},
                )
                continue
            if isinstance(result, VerifiedResult) and result.verdict == "CONFIRMED":
                # Convert VerifiedResult to Finding
                confirmed_findings.append(
                    Finding(
                        vulnerability_type=result.finding.vulnerability_type,
                        severity=result.finding.severity,
                        file_path=result.finding.file_path,
                        line_number=result.finding.line_number,
                        description=result.finding.description,
                        evidence=result.finding.evidence,
                        remediation=result.finding.remediation,
                        verified=True,
                        confidence=result.confidence,
                    )
                )

        logger.info(
            "Verifier processed %s findings, confirmed %s",
            len(findings),
            len(confirmed_findings),
            extra={"scan_id": scan_id, "confirmed_count": len(confirmed_findings)},
        )
        return confirmed_findings

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Verifier agent failed: %s",
            exc,
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        return []


async def _verify_single_finding(
    finding: PotentialFinding, diff_content: str, scan_id: str
) -> VerifiedResult | None:
    """Verify a single finding using the Verifier agent."""
    try:
        result = await _build_verifier_agent().run(
            "Verify this security finding:\n"
            f"{finding.model_dump_json()}\n\n"
            f"Code context:\n{diff_content}"
        )

        verdict = _parse_verifier_verdict(_result_text(result))
        verdict_obj = VerifiedResult(
            finding=finding,
            verdict=verdict.get("verdict", "UNCERTAIN"),
            confidence=verdict.get("confidence", 50),
            explanation=verdict.get("explanation", ""),
            trace_id=scan_id,
        )
        logger.info(
            "Finding verdict: %s",
            verdict_obj.verdict,
            extra={
                "scan_id": scan_id,
                "vulnerability_type": finding.vulnerability_type,
                "confidence": verdict_obj.confidence,
            },
        )
        return verdict_obj

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Verifier failed for finding: %s",
            exc,
            extra={"scan_id": scan_id, "finding_type": finding.vulnerability_type},
        )
        return None


@retry_on_llm_error(max_retries=3)
async def run_reporter_agent(
    findings: list[Finding], repository: str, commit_hash: str, scan_id: str
) -> str:
    """Execute Reporter agent to generate Markdown summary.

    Only runs after all Verifier tasks have completed (via orchestration).

    Args:
        findings: List of verified Finding objects from Verifier.
        repository: Repository name.
        commit_hash: Commit hash.
        scan_id: Trace ID for logging.

    Returns:
        str: Markdown-formatted security report.
    """
    logger.info(
        "Starting reporter agent",
        extra={"scan_id": scan_id, "finding_count": len(findings)},
    )

    if not _google_api_key_configured():
        logger.warning(
            "Skipping reporter agent: GOOGLE_API_KEY is not configured",
            extra={"scan_id": scan_id},
        )
        return (
            "## Security Scan Report\n"
            f"Repository: {repository}\n"
            f"Commit: {commit_hash}\n"
            f"Scan ID: {scan_id}\n\n"
            "Model-backed report generation skipped because GOOGLE_API_KEY is "
            "not configured."
        )

    try:
        findings_json = json.dumps([f.model_dump() for f in findings])
        result = await _build_reporter_agent().run(
            "Generate a GitHub-friendly Markdown report for:\n"
            f"Repository: {repository}\n"
            f"Commit: {commit_hash}\n"
            f"Findings:\n{findings_json}"
        )
        logger.info("Reporter generated Markdown summary", extra={"scan_id": scan_id})
        return _result_text(result)

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Reporter agent failed: %s",
            exc,
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        return (
            "## Security Scan Report\n"
            f"Repository: {repository}\n"
            f"Commit: {commit_hash}\n"
            f"Scan ID: {scan_id}\n\n"
            "Report generation failed. Please check logs."
        )
