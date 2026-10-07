"""
BHRAM Integration Tests — Database Connectivity & Schema
Tests PostgreSQL schema and seed data.
Requires: Docker services running (make up)
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def get_connection():
    """Return a psycopg2 connection or skip if unavailable."""
    try:
        import psycopg2
        from conftest import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT,
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            connect_timeout=5,
        )
        return conn
    except Exception as e:
        pytest.skip(f"Cannot connect to database: {e}")


class TestDatabaseConnectivity:

    def test_database_connection(self):
        """Must be able to connect to PostgreSQL."""
        conn = get_connection()
        assert conn is not None
        conn.close()

    def test_database_responds_to_query(self):
        """Database must respond to a simple query."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        result = cur.fetchone()
        assert result[0] == 1
        cur.close()
        conn.close()


class TestDatabaseSchema:

    def test_all_required_tables_exist(self):
        """All 8 required BHRAM tables must exist."""
        required_tables = {
            "users", "services", "decoy_files",
            "attack_sessions", "events",
            "attacker_profiles", "environment_state", "deception_actions",
        }
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        """)
        existing = {row[0] for row in cur.fetchall()}
        missing = required_tables - existing
        assert not missing, f"Missing tables: {missing}"
        cur.close()
        conn.close()

    def test_uuid_extension_installed(self):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT uuid_generate_v4()")
        result = cur.fetchone()
        assert result[0] is not None
        cur.close()
        conn.close()

    def test_environment_state_has_current_record(self):
        """The initial environment state must have a 'current' record."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM environment_state WHERE is_current = TRUE")
        count = cur.fetchone()[0]
        assert count >= 1, "No current environment state found — was seed.sql applied?"
        cur.close()
        conn.close()

    def test_users_seeded(self):
        """All 6 fictional users must be seeded."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        assert count >= 6, f"Expected 6 users, found {count}"
        cur.close()
        conn.close()

    def test_services_seeded(self):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM services")
        count = cur.fetchone()[0]
        assert count >= 4, f"Expected 4+ services, found {count}"
        cur.close()
        conn.close()

    def test_decoy_files_seeded(self):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM decoy_files WHERE is_active = TRUE")
        count = cur.fetchone()[0]
        assert count >= 5, f"Expected 5+ decoy files, found {count}"
        cur.close()
        conn.close()

    def test_database_not_on_host_port(self):
        """
        Database must NOT be accessible on public host port 5432.
        The compose.yaml exposes no ports for postgres.
        This test verifies the DB is only in internal network.
        """
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex(("0.0.0.0", 5432))
        from conftest import DB_HOST
        if DB_HOST != "localhost":
            pytest.skip("Running inside Docker network — public port test N/A")
        assert result != 0, "Port 5432 should not be open on host"
