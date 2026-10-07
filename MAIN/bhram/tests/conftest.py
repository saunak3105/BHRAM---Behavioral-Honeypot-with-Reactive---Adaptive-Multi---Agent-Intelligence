"""
BHRAM Test Suite — Shared fixtures and configuration
"""

from __future__ import annotations

import os
import pytest
import requests

# Base URLs — default to localhost with standard ports
BHRAM_API_URL    = os.environ.get("BHRAM_API_URL",    "http://localhost:8000")
WEB_URL          = os.environ.get("WEB_URL",          "http://localhost:8080")
FILESERVER_URL   = os.environ.get("FILESERVER_URL",   "http://localhost:8081")

DB_HOST     = os.environ.get("POSTGRES_HOST",     "localhost")
DB_PORT     = int(os.environ.get("POSTGRES_PORT", "5432"))
DB_NAME     = os.environ.get("POSTGRES_DB",       "bhram_db")
DB_USER     = os.environ.get("POSTGRES_USER",     "bhram_user")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "devpassword_not_for_production")


@pytest.fixture(scope="session")
def api_url() -> str:
    return BHRAM_API_URL


@pytest.fixture(scope="session")
def web_url() -> str:
    return WEB_URL


@pytest.fixture(scope="session")
def fileserver_url() -> str:
    return FILESERVER_URL


@pytest.fixture(scope="session")
def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    return s
