"""Tests for MewsConnector retry logic and error handling."""

import pytest
import requests
import requests_mock as rm

from mews_full_audit_app import MewsConnector


BASE_URL = "https://api.test.com/api/connector/v1"


@pytest.fixture
def connector():
    return MewsConnector(
        base_url=BASE_URL,
        client_token="ct-test",
        access_token="at-test",
    )


class TestMewsConnectorPost:
    def test_successful_post(self, connector):
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Services/GetAll", json={"Services": [{"Id": "s1"}]})
            result = connector._post("Services/GetAll", {})
            assert result["Services"][0]["Id"] == "s1"
            assert len(connector.calls) == 1
            assert connector.calls[0].ok is True

    def test_records_api_call(self, connector):
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Test/Op", json={"data": True})
            connector._post("Test/Op", {})
            assert len(connector.calls) == 1
            call = connector.calls[0]
            assert call.operation == "Test/Op"
            assert call.ok is True
            assert call.status_code == 200
            assert call.duration_ms >= 0

    def test_http_error_raises(self, connector):
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Bad/Call", json={"Message": "Not found"}, status_code=404)
            with pytest.raises(RuntimeError, match="HTTP 404"):
                connector._post("Bad/Call", {})

    def test_retries_on_500(self, connector):
        """Should retry on 500 and succeed on subsequent attempt."""
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Retry/Test", [
                {"json": {"error": "Internal"}, "status_code": 500},
                {"json": {"data": "ok"}, "status_code": 200},
            ])
            # Override backoff for faster tests
            connector._RETRY_BACKOFF_BASE = 0.01
            result = connector._post("Retry/Test", {})
            assert result["data"] == "ok"
            assert m.call_count == 2

    def test_retries_on_429(self, connector):
        """Should retry on 429 Too Many Requests."""
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Rate/Limit", [
                {"json": {"error": "Rate limited"}, "status_code": 429, "headers": {"Retry-After": "0.01"}},
                {"json": {"ok": True}, "status_code": 200},
            ])
            connector._RETRY_BACKOFF_BASE = 0.01
            result = connector._post("Rate/Limit", {})
            assert result["ok"] is True

    def test_non_retryable_error_fails_immediately(self, connector):
        """Should not retry on 400 Bad Request."""
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Bad/Request", json={"Message": "Bad"}, status_code=400)
            with pytest.raises(RuntimeError, match="HTTP 400"):
                connector._post("Bad/Request", {})
            assert m.call_count == 1

    def test_retries_on_connection_error(self, connector):
        """Should retry on network errors."""
        call_count = 0

        def custom_matcher(request, context):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.ConnectionError("Connection refused")
            context.status_code = 200
            return {"result": "ok"}

        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Net/Error", json=custom_matcher)
            connector._RETRY_BACKOFF_BASE = 0.01
            result = connector._post("Net/Error", {})
            assert result["result"] == "ok"


class TestMewsConnectorPagedGetAll:
    def test_single_page(self, connector):
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Items/GetAll", json={"Items": [{"Id": "1"}, {"Id": "2"}]})
            result = connector.paged_get_all("Items", "GetAll", {}, "Items")
            assert len(result) == 2

    def test_pagination(self, connector):
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Items/GetAll", [
                {"json": {"Items": [{"Id": "1"}], "Cursor": "abc"}},
                {"json": {"Items": [{"Id": "2"}]}},
            ])
            result = connector.paged_get_all("Items", "GetAll", {}, "Items")
            assert len(result) == 2

    def test_hard_limit(self, connector):
        with rm.Mocker() as m:
            m.post(f"{BASE_URL}/Items/GetAll", json={
                "Items": [{"Id": str(i)} for i in range(100)],
                "Cursor": "next",
            })
            result = connector.paged_get_all("Items", "GetAll", {}, "Items", hard_limit=50)
            assert len(result) <= 100  # Should stop after hard limit
