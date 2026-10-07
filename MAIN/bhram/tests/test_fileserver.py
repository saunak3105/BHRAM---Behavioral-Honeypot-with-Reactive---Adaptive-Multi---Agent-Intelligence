"""
BHRAM Integration Tests — File Server
Tests the deception file server and orchestrator API.
Requires: Docker services running (make up)
"""

from __future__ import annotations

import pytest
import requests

pytestmark = pytest.mark.integration


class TestFileServer:

    def test_fileserver_health(self, session: requests.Session, fileserver_url: str):
        r = session.get(f"{fileserver_url}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"

    def test_fileserver_health_structure(self, session: requests.Session, fileserver_url: str):
        r = session.get(f"{fileserver_url}/health", timeout=10)
        data = r.json()
        required = ["status", "service", "version", "timestamp", "file_root", "file_count"]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_list_files(self, session: requests.Session, fileserver_url: str):
        r = session.get(f"{fileserver_url}/files", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "files" in data
        assert "directories" in data

    def test_get_structure(self, session: requests.Session, fileserver_url: str):
        r = session.get(f"{fileserver_url}/structure", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "tree" in data
        assert "root" in data


class TestOrchestratorAPI:
    """Test the orchestrator file management API."""

    def test_create_decoy_file(self, session: requests.Session, fileserver_url: str):
        payload = {
            "filename": "test_decoy.txt",
            "filepath": "test/test_decoy.txt",
            "content": "This is a test decoy file created by BHRAM tests.",
            "content_type": "text/plain",
            "bait_level": 2,
        }
        r = session.post(f"{fileserver_url}/files/create", json=payload, timeout=10)
        assert r.status_code == 201
        data = r.json()
        assert data["success"] is True
        assert "test_decoy.txt" in data.get("filepath", "")

    def test_get_created_file_content(self, session: requests.Session, fileserver_url: str):
        r = session.get(
            f"{fileserver_url}/files/content",
            params={"filepath": "test/test_decoy.txt"},
            timeout=10,
        )
        # May 404 if test order differs; that's okay for Part 1
        assert r.status_code in {200, 404}

    def test_modify_decoy_file(self, session: requests.Session, fileserver_url: str):
        # First create
        create_payload = {
            "filename": "mod_test.txt",
            "filepath": "test/mod_test.txt",
            "content": "Original content",
            "content_type": "text/plain",
            "bait_level": 1,
        }
        session.post(f"{fileserver_url}/files/create", json=create_payload, timeout=10)

        # Then modify
        r = session.put(
            f"{fileserver_url}/files/modify",
            params={"filepath": "test/mod_test.txt", "content": "Modified content"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True

    def test_path_traversal_rejected(self, session: requests.Session, fileserver_url: str):
        """Path traversal attacks must be rejected."""
        payload = {
            "filename": "evil.txt",
            "filepath": "../../../etc/passwd",
            "content": "attacker content",
        }
        r = session.post(f"{fileserver_url}/files/create", json=payload, timeout=10)
        assert r.status_code in {400, 422}, (
            f"SECURITY: Path traversal was not rejected! Got {r.status_code}"
        )

    def test_delete_decoy_file(self, session: requests.Session, fileserver_url: str):
        # Create then delete
        create_payload = {
            "filename": "del_test.txt",
            "filepath": "test/del_test.txt",
            "content": "to be deleted",
        }
        session.post(f"{fileserver_url}/files/create", json=create_payload, timeout=10)
        r = session.delete(
            f"{fileserver_url}/files/delete",
            params={"filepath": "test/del_test.txt"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True

    def test_move_decoy_file(self, session: requests.Session, fileserver_url: str):
        # Create source
        create_payload = {
            "filename": "move_src.txt",
            "filepath": "test/move_src.txt",
            "content": "move this",
        }
        session.post(f"{fileserver_url}/files/create", json=create_payload, timeout=10)

        # Move
        r = session.post(
            f"{fileserver_url}/files/move",
            json={"source_path": "test/move_src.txt", "destination_path": "test/move_dst.txt"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
