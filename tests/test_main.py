"""
Example test file showing how to test the Rupert Security Conductor.
Run with: pytest tests/test_main.py
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check(self):
        """Test health endpoint returns 200."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        assert "version" in response.json()
        assert "timestamp" in response.json()


class TestScanEndpoint:
    """Tests for scan endpoint."""

    def test_scan_with_sql_injection(self):
        """Test scan detects SQL injection vulnerability."""
        payload = {
            "repository": "test-repo",
            "branch": "main",
            "commit_hash": "abc123",
            "code_diff": """
            - const query = "SELECT * FROM users WHERE id = " + userId;
            + const query = db.prepared("SELECT * FROM users WHERE id = ?", [userId]);
            """,
            "author": "test@example.com",
        }

        response = client.post("/scan", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "scan_id" in data
        assert data["repository"] == "test-repo"
        assert data["commit_hash"] == "abc123"
        assert "findings" in data
        assert "summary" in data

    def test_scan_no_vulnerabilities(self):
        """Test scan with clean code."""
        payload = {
            "repository": "test-repo",
            "branch": "main",
            "commit_hash": "def456",
            "code_diff": """
            + def greet(name):
            +     return f"Hello, {name}!"
            """,
            "author": "test@example.com",
        }

        response = client.post("/scan", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "scan_id" in data
        # Clean code may have no findings
        assert isinstance(data["findings"], list)

    def test_scan_missing_fields(self):
        """Test scan with missing required fields."""
        payload = {
            "repository": "test-repo",
            # Missing other required fields
        }

        response = client.post("/scan", json=payload)
        assert response.status_code == 422  # Validation error


class TestModels:
    """Tests for Pydantic models."""

    def test_finding_model(self):
        """Test Finding model validation."""
        from app.models import Finding, Severity, VulnerabilityType

        finding = Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            file_path="app.py",
            line_number=42,
            description="SQL injection found",
            evidence="query = 'SELECT * FROM users WHERE id = ' + id",
            remediation="Use parameterized queries",
        )

        assert finding.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert finding.severity == Severity.CRITICAL
        assert finding.verified is True

    def test_scan_request_model(self):
        """Test ScanRequest model."""
        from app.models import ScanRequest

        request = ScanRequest(
            repository="my-repo",
            branch="main",
            commit_hash="abc123",
            code_diff="diff content",
        )

        assert request.repository == "my-repo"
        assert request.author == "webhook"  # Default value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
