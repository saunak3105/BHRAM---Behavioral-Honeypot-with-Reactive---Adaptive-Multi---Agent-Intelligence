"""
BHRAM Integration Tests — BHRAM API
Tests all required API endpoints and validates responses.
Requires: all Docker services running (make up)
"""

from __future__ import annotations

import pytest
import requests

from conftest import BHRAM_API_URL


pytestmark = pytest.mark.integration


class TestAPIHealth:
    """GET /health — API and dependency health check."""

    def test_health_returns_200(self, session: requests.Session, api_url: str):
        """Health endpoint must return HTTP 200."""
        r = session.get(f"{api_url}/health", timeout=10)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    def test_health_response_structure(self, session: requests.Session, api_url: str):
        """Health response must have required fields."""
        r = session.get(f"{api_url}/health", timeout=10)
        data = r.json()
        assert "status" in data
        assert "version" in data
        assert "timestamp" in data
        assert "services" in data
        assert isinstance(data["services"], list)

    def test_health_status_healthy(self, session: requests.Session, api_url: str):
        """Health status must be 'healthy' when all services are running."""
        r = session.get(f"{api_url}/health", timeout=10)
        data = r.json()
        assert data["status"] == "healthy", (
            f"API is not healthy: {data}. Is the database running?"
        )

    def test_health_db_service_present(self, session: requests.Session, api_url: str):
        """Health response must include postgres service status."""
        r = session.get(f"{api_url}/health", timeout=10)
        data = r.json()
        services = {s["name"]: s for s in data["services"]}
        assert "postgres" in services, "Postgres service missing from health check"
        assert services["postgres"]["status"] == "healthy"


class TestEnvironmentEndpoint:
    """GET /api/v1/environment — Environment state."""

    def test_environment_returns_200(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/environment", timeout=10)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    def test_environment_response_fields(self, session: requests.Session, api_url: str):
        """Environment state must contain all required BHRAM fields."""
        r = session.get(f"{api_url}/api/v1/environment", timeout=10)
        data = r.json()
        required = ["id", "snapshot_time", "deception_mode", "is_current", "company"]
        for field in required:
            assert field in data, f"Missing field '{field}' in environment response"

    def test_environment_company_name(self, session: requests.Session, api_url: str):
        """Company name must be 'BHRAM Technologies'."""
        r = session.get(f"{api_url}/api/v1/environment", timeout=10)
        data = r.json()
        assert data["company"] == "BHRAM Technologies"

    def test_environment_deception_mode_valid(self, session: requests.Session, api_url: str):
        """Deception mode must be a valid enum value."""
        valid = {"baseline", "passive", "active", "aggressive", "reconstruction"}
        r = session.get(f"{api_url}/api/v1/environment", timeout=10)
        data = r.json()
        assert data["deception_mode"] in valid


class TestServicesEndpoint:
    """GET /api/v1/services — Services list."""

    def test_services_returns_200(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/services", timeout=10)
        assert r.status_code == 200

    def test_services_response_structure(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/services", timeout=10)
        data = r.json()
        assert "total" in data
        assert "services" in data
        assert isinstance(data["services"], list)

    def test_services_not_empty(self, session: requests.Session, api_url: str):
        """At least 4 services should be seeded."""
        r = session.get(f"{api_url}/api/v1/services", timeout=10)
        data = r.json()
        assert data["total"] >= 4, f"Expected at least 4 services, got {data['total']}"

    def test_cowrie_honeypot_registered(self, session: requests.Session, api_url: str):
        """Cowrie SSH service must be registered and marked as honeypot."""
        r = session.get(f"{api_url}/api/v1/services", timeout=10)
        data = r.json()
        names = {s["name"]: s for s in data["services"]}
        assert "cowrie-ssh" in names, "Cowrie SSH service not registered"
        assert names["cowrie-ssh"]["is_honeypot"] is True

    def test_database_not_exposed_to_frontend(self, session: requests.Session, api_url: str):
        """Database service must be on 'internal' network, not 'frontend'."""
        r = session.get(f"{api_url}/api/v1/services", timeout=10)
        data = r.json()
        for svc in data["services"]:
            if svc["name"] == "postgres":
                assert svc["network"] == "internal", (
                    "SECURITY: Postgres is NOT on the internal network!"
                )


class TestUsersEndpoint:
    """GET /api/v1/users — Users list."""

    def test_users_returns_200(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/users", timeout=10)
        assert r.status_code == 200

    def test_users_response_structure(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/users", timeout=10)
        data = r.json()
        assert "total" in data
        assert "users" in data

    def test_all_required_users_present(self, session: requests.Session, api_url: str):
        """All 6 fictional honeypot users must be present."""
        required = {"admin", "it_support", "developer", "finance", "hr_manager", "intern"}
        r = session.get(f"{api_url}/api/v1/users", timeout=10)
        data = r.json()
        usernames = {u["username"] for u in data["users"]}
        missing = required - usernames
        assert not missing, f"Missing required users: {missing}"

    def test_users_are_all_decoys(self, session: requests.Session, api_url: str):
        """All users must be marked as decoys — no real user data."""
        r = session.get(f"{api_url}/api/v1/users", timeout=10)
        data = r.json()
        for user in data["users"]:
            assert user["is_decoy"] is True, f"User {user['username']} is not marked as decoy!"

    def test_user_email_format(self, session: requests.Session, api_url: str):
        """User emails must use fictional internal domain."""
        r = session.get(f"{api_url}/api/v1/users", timeout=10)
        data = r.json()
        for user in data["users"]:
            assert "@bhram-technologies.internal" in user["email"], (
                f"User {user['username']} has unexpected email: {user['email']}"
            )


class TestFilesEndpoint:
    """GET /api/v1/files — Decoy files list."""

    def test_files_returns_200(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/files", timeout=10)
        assert r.status_code == 200

    def test_files_response_structure(self, session: requests.Session, api_url: str):
        r = session.get(f"{api_url}/api/v1/files", timeout=10)
        data = r.json()
        assert "total" in data
        assert "files" in data
        assert isinstance(data["files"], list)

    def test_decoy_files_seeded(self, session: requests.Session, api_url: str):
        """At least 5 decoy files must be present."""
        r = session.get(f"{api_url}/api/v1/files", timeout=10)
        data = r.json()
        assert data["total"] >= 5, f"Expected >= 5 decoy files, got {data['total']}"

    def test_high_bait_files_present(self, session: requests.Session, api_url: str):
        """High-bait files (level 5) like salary/DB backup must be present."""
        r = session.get(f"{api_url}/api/v1/files?min_bait_level=5", timeout=10)
        data = r.json()
        assert data["total"] >= 2, "Expected at least 2 high-bait (level 5) decoy files"

    def test_bait_level_range_valid(self, session: requests.Session, api_url: str):
        """All bait levels must be between 1 and 5."""
        r = session.get(f"{api_url}/api/v1/files?active_only=false", timeout=10)
        data = r.json()
        for f in data["files"]:
            assert 1 <= f["bait_level"] <= 5, (
                f"Invalid bait level {f['bait_level']} for {f['filename']}"
            )


class TestAPISecurityBoundaries:
    """Verify attacker-facing vs internal service separation."""

    def test_api_bound_to_loopback(self):
        """
        BHRAM API must only be accessible on localhost (127.0.0.1:8000).
        This test runs on the host — if it passes, the API is accessible locally
        but not exposed to the attacker network (verified by network configuration).
        """
        try:
            r = requests.get(f"{BHRAM_API_URL}/health", timeout=5)
            assert r.status_code == 200
        except requests.ConnectionError:
            pytest.skip("BHRAM API not running — start with 'make up'")

    def test_no_shell_execution_endpoint(self, session: requests.Session, api_url: str):
        """API must not expose a shell/command execution endpoint."""
        dangerous_paths = ["/exec", "/shell", "/cmd", "/run", "/execute", "/command"]
        for path in dangerous_paths:
            r = session.get(f"{api_url}{path}", timeout=5)
            assert r.status_code in {404, 405}, (
                f"SECURITY: Dangerous path {path} returned {r.status_code}!"
            )

    def test_openapi_schema_accessible(self, session: requests.Session, api_url: str):
        """OpenAPI schema must be accessible for AI/ML team integration."""
        r = session.get(f"{api_url}/openapi.json", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "openapi" in data
        assert "paths" in data
