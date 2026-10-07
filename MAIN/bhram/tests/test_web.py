"""
BHRAM Integration Tests — Web Application
Tests the fake company web application honeypot surface.
Requires: Docker services running (make up)
"""

from __future__ import annotations

import pytest
import requests

pytestmark = pytest.mark.integration


class TestWebApplication:
    """Verify the fake company web application is running and serving content."""

    def test_home_page_returns_200(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/", timeout=10)
        assert r.status_code == 200

    def test_home_page_contains_company_name(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/", timeout=10)
        assert "BHRAM Technologies" in r.text

    def test_about_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/about", timeout=10)
        assert r.status_code == 200
        assert "BHRAM" in r.text

    def test_careers_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/careers", timeout=10)
        assert r.status_code == 200

    def test_contact_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/contact", timeout=10)
        assert r.status_code == 200

    def test_employee_portal(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/employee", timeout=10)
        assert r.status_code == 200

    def test_login_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/login", timeout=10)
        assert r.status_code == 200
        assert "sign in" in r.text.lower() or "login" in r.text.lower()

    def test_support_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/support", timeout=10)
        assert r.status_code == 200

    def test_internal_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/internal", timeout=10)
        assert r.status_code == 200

    def test_documents_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/documents", timeout=10)
        assert r.status_code == 200

    def test_login_honeypot_always_fails(self, session: requests.Session, web_url: str):
        """Login must ALWAYS reject credentials — it's a honeypot."""
        s = requests.Session()
        r = s.post(
            f"{web_url}/login",
            data={"username": "admin", "password": "admin123"},
            allow_redirects=True,
            timeout=10,
        )
        # Should stay on login page or redirect back — NOT grant access
        assert "employee dashboard" not in r.text.lower()
        assert "welcome, admin" not in r.text.lower()

    def test_404_returns_custom_page(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/this-page-does-not-exist-abc123", timeout=10)
        assert r.status_code == 404

    def test_deception_artifacts_in_page(self, session: requests.Session, web_url: str):
        """Internal hostnames should appear as deception artifacts in page source."""
        r = session.get(f"{web_url}/internal", timeout=10)
        # At least one internal hostname reference should appear
        assert "bhram-technologies.internal" in r.text

    def test_content_type_html(self, session: requests.Session, web_url: str):
        r = session.get(f"{web_url}/", timeout=10)
        assert "text/html" in r.headers.get("Content-Type", "")
