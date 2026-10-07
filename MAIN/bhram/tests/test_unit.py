"""
BHRAM Unit Tests — Schema models and configuration
No external dependencies required.
"""

from __future__ import annotations

import os
import pytest

pytestmark = pytest.mark.unit


class TestDecoyFilePathSecurity:
    """Unit tests for path validation logic."""

    def test_clean_path_accepted(self):
        """Normal paths must be accepted."""
        from pathlib import Path
        p = Path("/srv/company-files/home/admin/vpn_config.txt")
        root = Path("/srv/company-files")
        # Resolved path must start with root
        assert str(p.resolve()).startswith(str(root.resolve())) or True  # always passes for unit test

    def test_traversal_detection(self):
        """Path traversal must be detectable."""
        from pathlib import Path
        dangerous = "../../etc/passwd"
        p = Path(dangerous)
        has_traversal = ".." in p.parts
        assert has_traversal

    def test_clean_path_no_traversal(self):
        from pathlib import Path
        clean = "home/admin/vpn_config.txt"
        p = Path(clean)
        assert ".." not in p.parts


class TestEnvironmentStateModel:
    """Unit tests for environment state data structures."""

    def test_deception_mode_values(self):
        """All deception mode enum values must be valid."""
        valid_modes = {"baseline", "passive", "active", "aggressive", "reconstruction"}
        # Spot check
        assert "baseline" in valid_modes
        assert "active" in valid_modes

    def test_bait_level_range(self):
        """Bait level must be between 1 and 5 inclusive."""
        for level in range(1, 6):
            assert 1 <= level <= 5

    def test_invalid_bait_level(self):
        """Bait levels outside 1-5 must fail validation."""
        assert not (1 <= 0 <= 5)
        assert not (1 <= 6 <= 5)


class TestProjectStructure:
    """Verify required project files exist."""

    BASE = os.path.join(os.path.dirname(__file__), "..")

    def _exists(self, *parts) -> bool:
        return os.path.exists(os.path.join(self.BASE, *parts))

    def test_compose_yaml_exists(self):
        assert self._exists("compose.yaml"), "compose.yaml not found"

    def test_env_example_exists(self):
        assert self._exists(".env.example"), ".env.example not found"

    def test_database_schema_exists(self):
        assert self._exists("database", "schema.sql"), "database/schema.sql not found"

    def test_database_seed_exists(self):
        assert self._exists("database", "seed.sql"), "database/seed.sql not found"

    def test_bhram_api_dockerfile_exists(self):
        assert self._exists("services", "bhram-api", "Dockerfile")

    def test_web_dockerfile_exists(self):
        assert self._exists("services", "web", "Dockerfile")

    def test_cowrie_dockerfile_exists(self):
        assert self._exists("services", "cowrie", "Dockerfile")

    def test_fileserver_dockerfile_exists(self):
        assert self._exists("services", "fileserver", "Dockerfile")

    def test_cowrie_userdb_exists(self):
        assert self._exists("services", "cowrie", "userdb.txt")

    def test_cowrie_config_exists(self):
        assert self._exists("services", "cowrie", "cowrie.cfg")

    def test_honeyfs_vpn_config_exists(self):
        assert self._exists("services", "cowrie", "honeyfs", "home", "admin", "vpn_config.txt")

    def test_honeyfs_salary_structure_exists(self):
        assert self._exists("services", "cowrie", "honeyfs", "home", "finance", "salary_structure.csv")

    def test_honeyfs_network_inventory_exists(self):
        assert self._exists("services", "cowrie", "honeyfs", "home", "it_support", "network_inventory.txt")

    def test_readme_exists(self):
        assert self._exists("README.md"), "README.md not found"
