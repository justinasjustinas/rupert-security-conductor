"""Endpoint tests for Rupert Security Conductor.

Covers: health, auth, rate limiting, input validation, security headers,
GitHub webhook, and Bitbucket webhook handlers.

Agent calls are mocked throughout so tests run without a Gemini API key.
"""

import hashlib
import hmac
import json
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import ScanResult


# ============================================================================
# HELPERS
# ============================================================================


def _mock_result(**kwargs) -> ScanResult:
    defaults = dict(
        scan_id="test-scan-id",
        timestamp=datetime.utcnow(),
        repository="test-repo",
        commit_hash="abc123",
        findings=[],
        summary="No findings",
        total_vulnerabilities=0,
        critical_count=0,
        high_count=0,
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _gh_sig(body: bytes, secret: str = "gh-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _bb_sig(body: bytes, secret: str = "bb-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


VALID_PAYLOAD = {
    "repository": "test-repo",
    "branch": "main",
    "commit_hash": "abc123",
    "code_diff": "+ def hello(): pass",
    "author": "tester",
}


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limit():
    """Clear in-process rate-limit state before and after every test."""
    import app.main as m
    m._rate_limit_store.clear()
    yield
    m._rate_limit_store.clear()


# ============================================================================
# HEALTH
# ============================================================================


class TestHealth:
    def test_returns_200(self, client):
        assert client.get("/health").status_code == 200

    def test_body_fields(self, client):
        data = client.get("/health").json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data


# ============================================================================
# SECURITY HEADERS
# ============================================================================


class TestSecurityHeaders:
    """Every response should carry the defensive HTTP headers."""

    def test_headers_on_health(self, client):
        h = client.get("/health").headers
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert "max-age=" in h["Strict-Transport-Security"]
        assert h["Cache-Control"] == "no-store"

    def test_headers_on_scan_error(self, client, monkeypatch):
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        monkeypatch.delenv("SCAN_AUTH_DISABLED", raising=False)
        h = client.post("/scan", json=VALID_PAYLOAD).headers
        assert h["X-Content-Type-Options"] == "nosniff"


# ============================================================================
# AUTH
# ============================================================================


class TestScanAuth:
    """Bearer-token auth on POST /scan."""

    def test_no_token_configured_returns_503(self, client, monkeypatch):
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        monkeypatch.delenv("SCAN_AUTH_DISABLED", raising=False)
        assert client.post("/scan", json=VALID_PAYLOAD).status_code == 503

    def test_auth_disabled_allows_unauthenticated(self, client, monkeypatch):
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            assert client.post("/scan", json=VALID_PAYLOAD).status_code == 200

    def test_missing_authorization_header_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_API_TOKEN", "secret")
        assert client.post("/scan", json=VALID_PAYLOAD).status_code == 401

    def test_wrong_token_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_API_TOKEN", "secret")
        r = client.post("/scan", json=VALID_PAYLOAD, headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_correct_token_returns_200(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_API_TOKEN", "secret")
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            r = client.post("/scan", json=VALID_PAYLOAD, headers={"Authorization": "Bearer secret"})
        assert r.status_code == 200

    def test_non_bearer_scheme_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_API_TOKEN", "secret")
        r = client.post("/scan", json=VALID_PAYLOAD, headers={"Authorization": "Basic secret"})
        assert r.status_code == 401


# ============================================================================
# RATE LIMITING
# ============================================================================


class TestRateLimit:
    """Sliding-window rate limiter on POST /scan."""

    @pytest.fixture(autouse=True)
    def low_limit(self):
        import app.main as m
        original = m._RATE_LIMIT_MAX
        m._RATE_LIMIT_MAX = 2
        yield
        m._RATE_LIMIT_MAX = original

    def _post(self, client):
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            return client.post("/scan", json=VALID_PAYLOAD)

    def test_requests_within_limit_succeed(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        for _ in range(2):
            assert self._post(client).status_code == 200

    def test_request_exceeding_limit_returns_429(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        self._post(client)
        self._post(client)
        assert self._post(client).status_code == 429

    def test_retry_after_header_on_429(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        self._post(client)
        self._post(client)
        r = self._post(client)
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) > 0

    def test_rate_limit_checked_after_auth(self, client, monkeypatch):
        """Auth failure should not consume a rate-limit slot."""
        monkeypatch.setenv("SCAN_API_TOKEN", "secret")
        # Two bad-auth requests do not fill the bucket
        for _ in range(2):
            client.post("/scan", json=VALID_PAYLOAD, headers={"Authorization": "Bearer wrong"})
        # A valid request should still succeed (bucket not consumed by rejected calls)
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            r = client.post("/scan", json=VALID_PAYLOAD, headers={"Authorization": "Bearer secret"})
        assert r.status_code == 200


# ============================================================================
# INPUT VALIDATION
# ============================================================================


class TestInputValidation:
    def test_missing_required_fields_returns_422(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        assert client.post("/scan", json={"repository": "only-field"}).status_code == 422

    def test_oversized_diff_returns_413(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        import app.main as m
        original = m._MAX_DIFF_BYTES
        m._MAX_DIFF_BYTES = 10
        payload = {**VALID_PAYLOAD, "code_diff": "x" * 11}
        try:
            r = client.post("/scan", json=payload)
        finally:
            m._MAX_DIFF_BYTES = original
        assert r.status_code == 413


# ============================================================================
# SCAN RESPONSE SHAPE
# ============================================================================


class TestScanResponse:
    def test_response_contains_expected_fields(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            data = client.post("/scan", json=VALID_PAYLOAD).json()
        for field in ("scan_id", "repository", "commit_hash", "findings", "summary"):
            assert field in data

    def test_repository_echoed_in_response(self, client, monkeypatch):
        monkeypatch.setenv("SCAN_AUTH_DISABLED", "true")
        monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
        result = _mock_result(repository="my-repo", commit_hash="def456")
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=result)):
            data = client.post("/scan", json={**VALID_PAYLOAD, "repository": "my-repo"}).json()
        assert data["repository"] == "my-repo"


# ============================================================================
# GITHUB WEBHOOK
# ============================================================================


class TestGithubWebhook:
    def _body(self, extra: dict | None = None) -> bytes:
        payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "owner/repo", "name": "repo"},
            "after": "abc123",
            "pusher": {"name": "dev"},
            "diff_content": "+ def foo(): pass",
        }
        if extra:
            payload.update(extra)
        return json.dumps(payload).encode()

    def test_missing_secret_config_returns_500(self, client, monkeypatch):
        monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
        body = self._body()
        r = client.post(
            "/webhook/github",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": _gh_sig(body)},
        )
        assert r.status_code == 500

    def test_missing_signature_header_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
        body = self._body()
        r = client.post("/webhook/github", content=body, headers={"Content-Type": "application/json"})
        assert r.status_code == 401

    def test_wrong_signature_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
        body = self._body()
        r = client.post(
            "/webhook/github",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": "sha256=deadbeef"},
        )
        assert r.status_code == 401

    def test_non_branch_push_returns_skipped(self, client, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
        payload = {
            "repository": {"full_name": "owner/repo"},
            "after": "abc123",
            "pusher": {"name": "dev"},
        }
        body = json.dumps(payload).encode()
        r = client.post(
            "/webhook/github",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": _gh_sig(body)},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "skipped"

    def test_valid_branch_push_with_diff_returns_202(self, client, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
        body = self._body()
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            r = client.post(
                "/webhook/github",
                content=body,
                headers={"Content-Type": "application/json", "X-Hub-Signature-256": _gh_sig(body)},
            )
        assert r.status_code == 202
        assert r.json()["status"] == "accepted"
        assert "scan_id" in r.json()

    def test_push_with_no_diff_returns_skipped(self, client, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
        payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "owner/repo"},
            "after": "",
            "pusher": {"name": "dev"},
        }
        body = json.dumps(payload).encode()
        with patch("app.main._fetch_github_diff", new=AsyncMock(return_value="")):
            r = client.post(
                "/webhook/github",
                content=body,
                headers={"Content-Type": "application/json", "X-Hub-Signature-256": _gh_sig(body)},
            )
        assert r.json()["status"] == "skipped"
        assert r.json()["reason"] == "no_diff_available"

    def test_invalid_json_returns_400(self, client, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
        body = b"not-json"
        r = client.post(
            "/webhook/github",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": _gh_sig(body)},
        )
        assert r.status_code == 400


# ============================================================================
# BITBUCKET WEBHOOK
# ============================================================================


class TestBitbucketWebhook:
    def _body(self, extra: dict | None = None) -> bytes:
        payload = {
            "push": {"changes": [{"new": {"hash": "abc123"}}]},
            "repository": {"full_name": "owner/repo"},
            "diff_content": "+ def bar(): pass",
        }
        if extra:
            payload.update(extra)
        return json.dumps(payload).encode()

    def test_missing_secret_config_returns_500(self, client, monkeypatch):
        monkeypatch.delenv("BITBUCKET_WEBHOOK_SECRET", raising=False)
        body = self._body()
        r = client.post(
            "/webhook/bitbucket",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature": _bb_sig(body)},
        )
        assert r.status_code == 500

    def test_wrong_signature_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
        body = self._body()
        r = client.post(
            "/webhook/bitbucket",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature": "sha256=deadbeef"},
        )
        assert r.status_code == 401

    def test_push_with_no_changes_returns_skipped(self, client, monkeypatch):
        monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
        payload = {"push": {"changes": []}, "repository": {"full_name": "owner/repo"}}
        body = json.dumps(payload).encode()
        r = client.post(
            "/webhook/bitbucket",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature": _bb_sig(body)},
        )
        assert r.json()["status"] == "skipped"

    def test_valid_push_with_diff_returns_202(self, client, monkeypatch):
        monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
        body = self._body()
        with patch("app.main.orchestrate_security_scan", new=AsyncMock(return_value=_mock_result())):
            r = client.post(
                "/webhook/bitbucket",
                content=body,
                headers={"Content-Type": "application/json", "X-Hub-Signature": _bb_sig(body)},
            )
        assert r.status_code == 202
        assert r.json()["status"] == "accepted"
