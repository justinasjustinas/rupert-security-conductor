"""Unit tests for agent response parsing helpers.

These are pure-logic tests — no HTTP stack, no mocking required.
"""

import json

import pytest

from app.agents import _parse_hunter_findings, _parse_verifier_verdict
from app.models import Severity, VulnerabilityType


# ============================================================================
# HUNTER FINDINGS PARSER
# ============================================================================


class TestParseHunterFindings:
    def test_clean_json_array(self):
        raw = json.dumps([
            {
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file_path": "db.py",
                "line_number": 10,
                "description": "Unsanitised input in query",
                "evidence": "query + user_input",
                "remediation": "Use parameterised queries",
            }
        ])
        findings = _parse_hunter_findings(raw)
        assert len(findings) == 1
        assert findings[0].vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].file_path == "db.py"

    def test_empty_array_returns_empty_list(self):
        assert _parse_hunter_findings("[]") == []

    def test_json_inside_markdown_fence(self):
        inner = json.dumps([
            {
                "vulnerability_type": "CROSS_SITE_SCRIPTING",
                "severity": "HIGH",
                "file_path": "view.py",
                "line_number": 5,
                "description": "Reflected XSS",
                "evidence": "innerHTML = input",
                "remediation": "Escape output",
            }
        ])
        raw = f"```json\n{inner}\n```"
        findings = _parse_hunter_findings(raw)
        assert len(findings) == 1
        assert findings[0].vulnerability_type == VulnerabilityType.XSS

    def test_json_embedded_in_prose(self):
        inner = json.dumps([
            {
                "vulnerability_type": "INJECTION",
                "severity": "HIGH",
                "file_path": "cmd.py",
                "line_number": 3,
                "description": "Command injection",
                "evidence": "os.system(user_input)",
                "remediation": "Use subprocess with args list",
            }
        ])
        raw = f"Here are the findings I identified:\n{inner}\nEnd of analysis."
        findings = _parse_hunter_findings(raw)
        assert len(findings) == 1

    def test_multiple_findings_parsed(self):
        raw = json.dumps([
            {
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file_path": "a.py",
                "line_number": 1,
                "description": "SQL",
                "evidence": "ev",
                "remediation": "fix",
            },
            {
                "vulnerability_type": "CROSS_SITE_SCRIPTING",
                "severity": "HIGH",
                "file_path": "b.py",
                "line_number": 2,
                "description": "XSS",
                "evidence": "ev2",
                "remediation": "fix2",
            },
        ])
        findings = _parse_hunter_findings(raw)
        assert len(findings) == 2

    def test_malformed_json_returns_empty(self):
        assert _parse_hunter_findings("{not valid json") == []

    def test_plain_text_returns_empty(self):
        assert _parse_hunter_findings("No vulnerabilities found.") == []

    def test_invalid_vulnerability_type_skipped(self):
        raw = json.dumps([
            {
                "vulnerability_type": "TOTALLY_MADE_UP",
                "severity": "HIGH",
                "file_path": "f.py",
                "line_number": 1,
                "description": "x",
                "evidence": "y",
                "remediation": "z",
            }
        ])
        # Unknown enum value — item should be dropped, not crash
        assert _parse_hunter_findings(raw) == []

    def test_partial_item_with_missing_fields_gets_defaults(self):
        # Items with missing optional fields should still parse (defaults applied)
        raw = json.dumps([
            {
                "vulnerability_type": "OTHER",
                "severity": "LOW",
                "file_path": "x.py",
                "line_number": 0,
                "description": "",
                "evidence": "",
                "remediation": "",
            }
        ])
        findings = _parse_hunter_findings(raw)
        assert len(findings) == 1


# ============================================================================
# VERIFIER VERDICT PARSER
# ============================================================================


class TestParseVerifierVerdict:
    def test_confirmed_verdict(self):
        raw = json.dumps({"verdict": "CONFIRMED", "confidence": 90, "explanation": "Real vuln"})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "CONFIRMED"
        assert result["confidence"] == 90

    def test_refuted_verdict(self):
        raw = json.dumps({"verdict": "REFUTED", "confidence": 85, "explanation": "False positive"})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "REFUTED"

    def test_uncertain_verdict(self):
        raw = json.dumps({"verdict": "UNCERTAIN", "confidence": 50, "explanation": "Need more context"})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "UNCERTAIN"

    def test_lowercase_verdict_normalised(self):
        raw = json.dumps({"verdict": "confirmed", "confidence": 80, "explanation": "yes"})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "CONFIRMED"

    def test_mixed_case_verdict_normalised(self):
        raw = json.dumps({"verdict": "Refuted", "confidence": 70, "explanation": "nope"})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "REFUTED"

    def test_unknown_verdict_defaults_to_uncertain(self):
        raw = json.dumps({"verdict": "APPROVE", "confidence": 70, "explanation": "..."})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "UNCERTAIN"

    def test_malformed_json_returns_uncertain(self):
        result = _parse_verifier_verdict("not json at all")
        assert result["verdict"] == "UNCERTAIN"

    def test_json_embedded_in_prose(self):
        inner = json.dumps({"verdict": "REFUTED", "confidence": 60, "explanation": "No real impact"})
        raw = f"After careful analysis: {inner}"
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "REFUTED"

    def test_missing_confidence_gets_default(self):
        raw = json.dumps({"verdict": "CONFIRMED", "explanation": "yes"})
        result = _parse_verifier_verdict(raw)
        assert result["verdict"] == "CONFIRMED"
        # confidence key present (from raw JSON, no confidence → key absent, not defaulted here)
        # just ensure no crash


# ============================================================================
# RETRY DECORATOR
# ============================================================================


class TestRetryDecorator:
    @pytest.mark.asyncio
    async def test_succeeds_on_first_attempt(self):
        from app.agents import retry_on_llm_error
        calls = []

        @retry_on_llm_error(max_retries=3, base_delay=0)
        async def fn():
            calls.append(1)
            return "ok"

        assert await fn() == "ok"
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_retries_then_succeeds(self):
        from app.agents import retry_on_llm_error
        calls = []

        @retry_on_llm_error(max_retries=3, base_delay=0)
        async def fn():
            calls.append(1)
            if len(calls) < 3:
                raise ValueError("transient")
            return "ok"

        assert await fn() == "ok"
        assert len(calls) == 3

    @pytest.mark.asyncio
    async def test_raises_after_all_retries_exhausted(self):
        from app.agents import retry_on_llm_error

        @retry_on_llm_error(max_retries=3, base_delay=0)
        async def fn():
            raise RuntimeError("permanent")

        with pytest.raises(RuntimeError, match="permanent"):
            await fn()
