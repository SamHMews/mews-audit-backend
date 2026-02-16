"""Integration tests for Flask endpoints."""

import json
import pytest
from unittest.mock import patch, MagicMock

from mews_full_audit_app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"


class TestAuditEndpoint:
    def test_missing_access_token(self, client):
        resp = client.post("/audit", data={"environment": "demo"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "access_token" in data.get("error", "").lower() or "missing" in data.get("error", "").lower()

    def test_missing_client_token(self, client):
        with patch.dict("os.environ", {"DEMO": "", "MEWS_CLIENT_TOKEN_DEMO": ""}, clear=False):
            resp = client.post("/audit", data={
                "access_token": "test-token",
                "environment": "demo",
            })
            # Should fail because no client token is configured
            assert resp.status_code in (400, 500, 502)

    def test_no_stack_trace_in_error(self, client):
        """Verify that server errors don't leak stack traces."""
        with patch("mews_full_audit_app.collect_data", side_effect=RuntimeError("Test error")):
            resp = client.post("/audit", data={
                "access_token": "test-token",
                "environment": "demo",
                "client_token": "test-ct",
                "base_url": "https://example.com/api/v1",
            })
            data = resp.get_json()
            assert "trace" not in data
            assert "traceback" not in str(data).lower()
            assert "RuntimeError" not in data.get("error", "")


class TestLookupEndpoint:
    def test_missing_access_token(self, client):
        resp = client.post("/lookup",
                           data=json.dumps({"environment": "demo", "item": "services"}),
                           content_type="application/json")
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "missing_access_token"

    def test_unsupported_item(self, client):
        with patch.dict("os.environ", {"DEMO": "test-client-token"}, clear=False):
            resp = client.post("/lookup",
                               data=json.dumps({
                                   "environment": "demo",
                                   "item": "nonexistent",
                                   "access_token": "test"
                               }),
                               content_type="application/json")
            assert resp.status_code == 400
            data = resp.get_json()
            assert "unsupported_item" in data.get("error", "")

    def test_invalid_access_token(self, client):
        resp = client.post("/lookup",
                           data=json.dumps({
                               "environment": "demo",
                               "item": "services",
                               "access_token": "import os\ndef hack():"
                           }),
                           content_type="application/json")
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "invalid_access_token"

    def test_server_error_returns_500(self, client):
        """Verify lookup errors return 500, not 200."""
        with patch("mews_full_audit_app.MewsConnector._post", side_effect=RuntimeError("API down")):
            resp = client.post("/lookup",
                               data=json.dumps({
                                   "environment": "demo",
                                   "item": "services",
                                   "access_token": "valid-token-format"
                               }),
                               content_type="application/json")
            assert resp.status_code == 500


class TestServeFrontend:
    def test_serves_index_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
