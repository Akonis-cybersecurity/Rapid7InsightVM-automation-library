import pytest
import requests_mock as requests_mock_module

from rapid7insightvm_modules.client import (
    InsightVMClient,
    InsightVMAPIError,
    InsightVMAuthError,
    InsightVMRateLimitError,
)

BASE_URL = "https://us.api.insight.rapid7.com"


@pytest.fixture
def client():
    return InsightVMClient(api_key="test-key", base_url=BASE_URL)


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------

def test_validate_success(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/validate", json={"message": "Authorized"})
    assert client.validate() is True


def test_validate_unauthorized(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/validate", json={"message": "Unauthorized"})
    assert client.validate() is False


# ---------------------------------------------------------------------------
# search_assets()
# ---------------------------------------------------------------------------

def test_search_assets_single_page(client, requests_mock):
    payload = {
        "data": [{"id": "asset-1", "ip": "10.0.0.1"}],
        "metadata": {"index": 0, "size": 500, "total_data": 1, "cursor": None},
    }
    requests_mock.post(f"{BASE_URL}/vm/v4/integration/assets", json=payload)
    result = client.search_assets({"size": 500})
    assert result["data"][0]["id"] == "asset-1"


def test_search_assets_sends_api_key_header(client, requests_mock):
    requests_mock.post(f"{BASE_URL}/vm/v4/integration/assets", json={"data": [], "metadata": {}})
    client.search_assets({})
    assert requests_mock.last_request.headers["X-Api-Key"] == "test-key"


# ---------------------------------------------------------------------------
# get_asset()
# ---------------------------------------------------------------------------

def test_get_asset_success(client, requests_mock):
    asset = {"id": "asset-42", "ip": "192.168.1.1", "risk_score": 9000}
    requests_mock.get(f"{BASE_URL}/vm/v4/integration/assets/asset-42", json=asset)
    result = client.get_asset("asset-42")
    assert result["id"] == "asset-42"
    assert result["risk_score"] == 9000


# ---------------------------------------------------------------------------
# search_vulnerabilities()
# ---------------------------------------------------------------------------

def test_search_vulnerabilities(client, requests_mock):
    payload = {
        "data": [{"id": "unix-anon-root", "severity": "severe", "cvss_v3_score": 8.4}],
        "metadata": {"index": 0, "size": 1, "total_data": 1, "cursor": None},
    }
    requests_mock.post(f"{BASE_URL}/vm/v4/integration/vulnerabilities", json=payload)
    result = client.search_vulnerabilities({"vulnerability": "vulnerability.vulnKey = 'unix-anon-root'", "size": 1})
    assert result["data"][0]["severity"] == "severe"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_auth_error_401(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/validate", status_code=401)
    with pytest.raises(InsightVMAuthError):
        client.validate()


def test_auth_error_403(client, requests_mock):
    requests_mock.post(f"{BASE_URL}/vm/v4/integration/assets", status_code=403)
    with pytest.raises(InsightVMAuthError):
        client.search_assets({})


def test_client_error_non_auth(client, requests_mock):
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/assets",
        status_code=400,
        json={"status": 400, "message": "Bad Request"},
    )
    with pytest.raises(InsightVMAPIError):
        client.search_assets({})


def test_rate_limit_exhausted(client, requests_mock):
    """429 on all attempts should raise InsightVMRateLimitError."""
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/assets",
        status_code=429,
    )
    # Patch RETRY_DELAYS to empty so there's no actual sleep in tests
    import rapid7insightvm_modules.client as client_mod
    original = client_mod.RETRY_DELAYS
    client_mod.RETRY_DELAYS = []
    try:
        with pytest.raises(InsightVMRateLimitError):
            client.search_assets({})
    finally:
        client_mod.RETRY_DELAYS = original


def test_server_error_retries_then_raises(client, requests_mock):
    """500 on all attempts should raise after retries."""
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/assets",
        status_code=500,
    )
    import rapid7insightvm_modules.client as client_mod
    original = client_mod.RETRY_DELAYS
    client_mod.RETRY_DELAYS = []
    try:
        with pytest.raises(InsightVMAPIError):
            client.search_assets({})
    finally:
        client_mod.RETRY_DELAYS = original


def test_trailing_slash_stripped():
    """base_url with trailing slash should not produce double-slash in URL."""
    c = InsightVMClient(api_key="k", base_url="https://eu.api.insight.rapid7.com/")
    assert c._base_url == "https://eu.api.insight.rapid7.com"
