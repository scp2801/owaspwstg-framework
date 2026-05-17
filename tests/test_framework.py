"""
Tests for OWASP WSTG Framework Core Modules
============================================
Run: pytest tests/ -v
"""

import sys
import os
import pytest
import asyncio

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConfigLoader:
    """Tests for configuration loading."""

    def test_default_config_loads(self):
        from core.config_loader import ConfigLoader
        config = ConfigLoader("config.yaml").load()
        assert "scan" in config
        assert "recon" in config
        assert "vulnerabilities" in config
        assert config["scan"]["threads"] > 0
        assert config["scan"]["timeout"] > 0

    def test_profile_fast(self):
        from core.config_loader import ConfigLoader
        loader = ConfigLoader("config.yaml")
        config = loader.load()
        config["scan"]["profile"] = "fast"
        assert config is not None

    def test_default_config_values(self):
        from core.config_loader import DEFAULT_CONFIG
        assert "framework" in DEFAULT_CONFIG
        assert "scan" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["scan"]["threads"] == 10


class TestUtils:
    """Tests for utility functions."""

    def test_normalize_url_adds_https(self):
        from core.utils import normalize_url
        assert normalize_url("example.com").startswith("https://")

    def test_normalize_url_keeps_http(self):
        from core.utils import normalize_url
        result = normalize_url("http://example.com")
        assert result.startswith("http://")

    def test_extract_domain(self):
        from core.utils import extract_domain
        assert extract_domain("https://www.example.com/path") == "www.example.com"
        assert extract_domain("example.com") == "example.com"

    def test_is_valid_domain(self):
        from core.utils import is_valid_domain
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("not a domain") is False
        assert is_valid_domain("") is False

    def test_deduplicate_list(self):
        from core.utils import deduplicate_list
        items = ["a", "b", "a", "c", "B"]
        result = deduplicate_list(items)
        assert len(result) == 4  # a, b, c, B (case-sensitive dedup by lowercase)

    def test_sanitize_filename(self):
        from core.utils import sanitize_filename
        assert "/" not in sanitize_filename("test/file:name")
        assert sanitize_filename("normal_name") == "normal_name"

    def test_extract_urls_from_text(self):
        from core.utils import extract_urls_from_text
        text = "Visit https://example.com and http://test.com for info"
        urls = extract_urls_from_text(text)
        assert len(urls) == 2
        assert "https://example.com" in urls

    def test_chunk_list(self):
        from core.utils import chunk_list
        result = chunk_list([1, 2, 3, 4, 5], 2)
        assert result == [[1, 2], [3, 4], [5]]

    def test_severity_to_color(self):
        from core.utils import severity_to_color
        assert "red" in severity_to_color("critical")
        assert "green" in severity_to_color("pass")


class TestOSDetector:
    """Tests for OS detection."""

    def test_detect_returns_dict(self):
        from core.os_detector import OSDetector
        info = OSDetector().detect()
        assert isinstance(info, dict)
        assert "is_termux" in info
        assert "is_kali" in info
        assert "is_linux" in info
        assert "name" in info
        assert "tools" in info

    def test_not_termux_in_test_env(self):
        from core.os_detector import OSDetector
        info = OSDetector().detect()
        # In a standard test environment, should not be Termux
        assert isinstance(info["is_termux"], bool)


class TestChecklistEngine:
    """Tests for OWASP WSTG checklist engine."""

    def test_checklist_initialized(self):
        from core.checklist_engine import ChecklistEngine
        engine = ChecklistEngine()
        assert len(engine.checklist) > 50  # Should have all WSTG items

    def test_mark_pass(self):
        from core.checklist_engine import ChecklistEngine, ChecklistStatus
        engine = ChecklistEngine()
        engine.mark_pass("WSTG-INFO-01", url="https://example.com")
        item = engine.checklist["WSTG-INFO-01"]
        assert item["status"] == ChecklistStatus.PASS

    def test_mark_fail(self):
        from core.checklist_engine import ChecklistEngine, ChecklistStatus
        engine = ChecklistEngine()
        engine.mark_fail("WSTG-INPV-01", evidence="XSS found", url="https://example.com?q=<xss>")
        item = engine.checklist["WSTG-INPV-01"]
        assert item["status"] == ChecklistStatus.FAIL
        assert len(item["evidence"]) > 0

    def test_mark_review(self):
        from core.checklist_engine import ChecklistEngine, ChecklistStatus
        engine = ChecklistEngine()
        engine.mark_review("WSTG-CONF-07", notes="Needs manual check")
        item = engine.checklist["WSTG-CONF-07"]
        assert item["status"] == ChecklistStatus.REVIEW

    def test_summary(self):
        from core.checklist_engine import ChecklistEngine
        engine = ChecklistEngine()
        engine.mark_pass("WSTG-INFO-01")
        engine.mark_fail("WSTG-INPV-05")
        summary = engine.get_summary()
        assert "status_counts" in summary
        assert summary["status_counts"]["PASS"] >= 1
        assert summary["status_counts"]["FAIL"] >= 1

    def test_get_failures(self):
        from core.checklist_engine import ChecklistEngine
        engine = ChecklistEngine()
        engine.mark_fail("WSTG-INPV-01", evidence="XSS")
        engine.mark_fail("WSTG-INPV-05", evidence="SQLi")
        failures = engine.get_failures()
        assert len(failures) == 2

    def test_get_by_category(self):
        from core.checklist_engine import ChecklistEngine
        engine = ChecklistEngine()
        by_cat = engine.get_by_category()
        assert "Information Gathering" in by_cat
        assert "Authentication" in by_cat

    def test_all_wstg_ids_present(self):
        from core.checklist_engine import ChecklistEngine
        engine = ChecklistEngine()
        required_ids = [
            "WSTG-INFO-01", "WSTG-CONF-07", "WSTG-ATHN-01",
            "WSTG-SESS-01", "WSTG-INPV-01", "WSTG-CLNT-01",
        ]
        for wstg_id in required_ids:
            assert wstg_id in engine.checklist, f"Missing WSTG ID: {wstg_id}"


class TestJWTChecker:
    """Tests for JWT vulnerability checker."""

    def test_decode_valid_jwt(self):
        from modules.vulnerabilities.jwt_checker import JWTChecker
        checker = JWTChecker([], {
            "scan": {"timeout": 10, "user_agent": "Test"}
        }, None)

        # Test JWT decoding
        import base64, json
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"1234","name":"Test"}').rstrip(b'=').decode()
        token = f"{header}.{payload}.fakesig"

        result = checker._decode_b64(header)
        assert result is not None
        data = json.loads(result)
        assert data["alg"] == "HS256"

    def test_extract_jwts_from_text(self):
        from modules.vulnerabilities.jwt_checker import JWTChecker
        checker = JWTChecker([], {
            "scan": {"timeout": 10, "user_agent": "Test"}
        }, None)
        text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fakesig"
        tokens = checker._extract_jwts(text)
        assert len(tokens) >= 1


class TestParamDiscovery:
    """Tests for parameter discovery."""

    def test_classify_param_idor(self):
        from modules.params.param_discovery import ParamDiscovery
        disc = ParamDiscovery([], {"scan": {"timeout": 10, "user_agent": "T"}}, None)
        assert disc._classify_param("user_id", "123") == "IDOR_CANDIDATE"

    def test_classify_param_redirect(self):
        from modules.params.param_discovery import ParamDiscovery
        disc = ParamDiscovery([], {"scan": {"timeout": 10, "user_agent": "T"}}, None)
        assert disc._classify_param("redirect", "https://evil.com") == "REDIRECT_CANDIDATE"

    def test_classify_param_xss(self):
        from modules.params.param_discovery import ParamDiscovery
        disc = ParamDiscovery([], {"scan": {"timeout": 10, "user_agent": "T"}}, None)
        assert disc._classify_param("search", "test") == "XSS_CANDIDATE"

    def test_extract_url_params(self):
        from modules.params.param_discovery import ParamDiscovery
        disc = ParamDiscovery([], {"scan": {"timeout": 10, "user_agent": "T"}}, None)
        results = disc._extract_url_params("https://example.com/search?q=test&page=1")
        assert len(results) == 2
        param_names = [r["param"] for r in results]
        assert "q" in param_names
        assert "page" in param_names


class TestSensitiveFilesChecker:
    """Tests for sensitive files checker."""

    def test_false_positive_404_page(self):
        from modules.vulnerabilities.sensitive_files import SensitiveFilesChecker
        checker = SensitiveFilesChecker([], {"scan": {"timeout": 10, "user_agent": "T"}}, None)
        body = "<html><body>404 Page Not Found</body></html>"
        assert checker._is_false_positive(body, "/.env") is True

    def test_not_false_positive_real_env(self):
        from modules.vulnerabilities.sensitive_files import SensitiveFilesChecker
        checker = SensitiveFilesChecker([], {"scan": {"timeout": 10, "user_agent": "T"}}, None)
        body = "APP_KEY=base64:abc123\nDB_PASSWORD=secret\nAPI_KEY=xyz789"
        assert checker._is_false_positive(body, "/.env") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
