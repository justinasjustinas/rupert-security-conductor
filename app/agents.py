"""Pydantic-AI agent definitions for security orchestration."""

import asyncio
import json
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

logger = get_logger(__name__)

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
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        delay = base_delay * (2**attempt)
                        logger.warning(
                            f"LLM call failed, retrying in {delay}s (attempt {attempt + 1}/{max_retries})",
                            extra={"error": str(e), "retry_attempt": attempt + 1},
                        )
                        await asyncio.sleep(delay)
            raise last_exception

        return async_wrapper  # type: ignore

    return decorator


# ============================================================================
# HUNTER AGENT: Scans code diffs for OWASP vulnerabilities
# ============================================================================

hunter_agent = Agent(
    model="gemini-1.5-flash",
    name="SecurityHunter",
    system_prompt="""You are a security vulnerability hunter scanning code diffs for OWASP vulnerabilities.

Analyze the provided code diff and identify:
1. SQL Injection vulnerabilities
2. Cross-Site Scripting (XSS) vulnerabilities
3. Authentication/Authorization bypasses
4. Insecure data transmission
5. Broken cryptography
6. Logic flaws
7. Other injection attacks

For each vulnerability found, provide:
- Type (from OWASP Top 10)
- Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- File path and approximate line number
- Clear description of the vulnerability
- Evidence from the code
- Recommended remediation

Return a JSON array of findings. If no vulnerabilities found, return empty array [].""",
)


@hunter_agent.tool
def analyze_code_diff(ctx: RunContext, diff_content: str) -> str:
    """Analyze a code diff for vulnerabilities."""
    logger.info(
        "hunter_agent analyzing code diff", extra={"diff_size": len(diff_content)}
    )
    return f"Analyzing code diff:\n{diff_content[:500]}..."


# ============================================================================
# VERIFIER AGENT: Adversarial agent that proves/disproves vulnerabilities
# ============================================================================

verifier_agent = Agent(
    model="gemini-1.5-flash",
    name="SecurityVerifier",
    system_prompt="""You are an adversarial security verifier. Your role is to validate findings from the Hunter agent.

For each potential vulnerability provided, determine:
1. Is this a real vulnerability or a false positive?
2. Can an attacker realistically exploit this?
3. Are there mitigating factors in the codebase?
4. What's the actual risk if exploited?

Reason through each finding systematically. Use logical deduction to either:
- CONFIRM: This is a legitimate vulnerability
- REFUTE: This is a false positive or not exploitable
- UNCERTAIN: Need more context

Provide your verdict and reasoning in JSON format with fields:
- finding_id: reference to original finding
- verdict: CONFIRMED | REFUTED | UNCERTAIN
- explanation: detailed reasoning
- confidence: 0-100 (confidence in your verdict)""",
)


@verifier_agent.tool
def validate_finding(ctx: RunContext, finding_json: str, code_context: str) -> str:
    """Validate a specific finding against code context."""
    logger.info("verifier_agent validating finding")
    return f"Validating finding with code context: {code_context[:300]}..."


# ============================================================================
# REPORTER AGENT: Aggregates findings into Markdown summary
# ============================================================================

reporter_agent = Agent(
    model="gemini-1.5-flash",
    name="SecurityReporter",
    system_prompt="""You are a security report generator. Your role is to aggregate verified findings and create clear, actionable Markdown reports for GitHub.

Given a list of verified vulnerabilities, generate a professional Markdown summary that includes:
1. Executive Summary (severity counts, risk level)
2. Detailed Findings (grouped by severity)
3. Remediation Recommendations (prioritized)
4. Scan Metadata (timestamp, commit hash, etc.)

Format the output as valid Markdown suitable for GitHub PR comments or issues.
Use tables for findings and code blocks for examples.""",
)


@reporter_agent.tool
def format_findings(ctx: RunContext, findings_json: str, repo_name: str) -> str:
    """Format findings into Markdown report."""
    logger.info("reporter_agent formatting findings", extra={"repo_name": repo_name})
    return f"Formatting {len(findings_json)} findings for repository {repo_name}..."


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
            except Exception as e:
                logger.warning(f"Failed to parse finding: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to parse hunter findings: {e}")

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
    except Exception as e:
        logger.warning(f"Failed to parse verifier verdict: {e}")

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

    try:
        # Run hunter agent with diff content
        result = await hunter_agent.run(
            f"Scan this code diff for vulnerabilities:\n\n{diff_content}",
        )

        # Parse findings from response
        findings = _parse_hunter_findings(result.data)
        logger.info(
            f"Hunter found {len(findings)} potential vulnerabilities",
            extra={"scan_id": scan_id, "finding_count": len(findings)},
        )
        return findings

    except Exception as e:
        logger.error(
            f"Hunter agent failed: {str(e)}", extra={"scan_id": scan_id}, exc_info=True
        )
        return []


@retry_on_llm_error(max_retries=3)
async def run_verifier_agent(
    findings: list[PotentialFinding], diff_content: str, scan_id: str
) -> list[Finding]:
    """Execute Verifier agent to validate findings (parallel processing).

    Verifier processes all findings in parallel and returns only CONFIRMED findings as verified Finding objects.

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
                    f"Verification task failed: {str(result)}",
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
            f"Verifier processed {len(findings)} findings, confirmed {len(confirmed_findings)}",
            extra={"scan_id": scan_id, "confirmed_count": len(confirmed_findings)},
        )
        return confirmed_findings

    except Exception as e:
        logger.error(
            f"Verifier agent failed: {str(e)}",
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        return []


async def _verify_single_finding(
    finding: PotentialFinding, diff_content: str, scan_id: str
) -> VerifiedResult | None:
    """Verify a single finding using the Verifier agent."""
    try:
        result = await verifier_agent.run(
            f"Verify this security finding:\n{finding.model_dump_json()}\n\nCode context:\n{diff_content}"
        )

        verdict = _parse_verifier_verdict(result.data)
        verdict_obj = VerifiedResult(
            finding=finding,
            verdict=verdict.get("verdict", "UNCERTAIN"),
            confidence=verdict.get("confidence", 50),
            explanation=verdict.get("explanation", ""),
            trace_id=scan_id,
        )
        logger.info(
            f"Finding verdict: {verdict_obj.verdict}",
            extra={
                "scan_id": scan_id,
                "vulnerability_type": finding.vulnerability_type,
                "confidence": verdict_obj.confidence,
            },
        )
        return verdict_obj

    except Exception as e:
        logger.warning(
            f"Verifier failed for finding: {str(e)}",
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

    try:
        findings_json = json.dumps([f.model_dump() for f in findings])
        result = await reporter_agent.run(
            f"Generate a GitHub-friendly Markdown report for:\nRepository: {repository}\nCommit: {commit_hash}\nFindings:\n{findings_json}"
        )
        logger.info("Reporter generated Markdown summary", extra={"scan_id": scan_id})
        return str(result.data)

    except Exception as e:
        logger.error(
            f"Reporter agent failed: {str(e)}",
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        return f"## Security Scan Report\nRepository: {repository}\nCommit: {commit_hash}\nScan ID: {scan_id}\n\nReport generation failed. Please check logs."
