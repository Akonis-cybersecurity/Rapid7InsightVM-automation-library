import pytest

from rapid7insightvm_modules.actions.get_asset import GetAssetAction, GetAssetArguments
from rapid7insightvm_modules.actions.get_vulnerability import (
    GetVulnerabilityAction,
    GetVulnerabilityArguments,
)

BASE_URL = "https://us.api.insight.rapid7.com"


# ---------------------------------------------------------------------------
# GetAssetAction
# ---------------------------------------------------------------------------

def test_get_asset_returns_full_asset(get_asset_action, requests_mock):
    asset = {
        "id": "asset-99",
        "ip": "172.16.0.10",
        "host_name": "prod-server.example.com",
        "risk_score": 18250,
        "critical_vulnerabilities": 3,
        "os_description": "Red Hat Enterprise Linux 7.9",
        "tags": [{"name": "production", "type": "SITE"}],
        "new": [],
        "remediated": [],
        "same": [],
    }
    requests_mock.get(f"{BASE_URL}/vm/v4/integration/assets/asset-99", json=asset)

    result = get_asset_action.run(GetAssetArguments(asset_id="asset-99"))
    assert result["id"] == "asset-99"
    assert result["risk_score"] == 18250
    assert result["os_description"] == "Red Hat Enterprise Linux 7.9"


def test_get_asset_sends_correct_url(get_asset_action, requests_mock):
    requests_mock.get(
        f"{BASE_URL}/vm/v4/integration/assets/my-asset-id",
        json={"id": "my-asset-id"},
    )
    get_asset_action.run(GetAssetArguments(asset_id="my-asset-id"))
    assert requests_mock.last_request.url == f"{BASE_URL}/vm/v4/integration/assets/my-asset-id"


def test_get_asset_sends_api_key_header(get_asset_action, requests_mock):
    requests_mock.get(
        f"{BASE_URL}/vm/v4/integration/assets/a1",
        json={"id": "a1"},
    )
    get_asset_action.run(GetAssetArguments(asset_id="a1"))
    assert requests_mock.last_request.headers["X-Api-Key"] == "test-api-key"


# ---------------------------------------------------------------------------
# GetVulnerabilityAction
# ---------------------------------------------------------------------------

def test_get_vulnerability_returns_definition(get_vulnerability_action, requests_mock):
    vuln = {
        "id": "unix-anonymous-root-logins",
        "title": "Anonymous root login is allowed",
        "severity": "severe",
        "severity_score": 7,
        "cvss_v3_score": 8.4,
        "cvss_v3_vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cves": "CVE-2024-1234",
        "exploits": [],
    }
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/vulnerabilities",
        json={"data": [vuln], "metadata": {"index": 0, "size": 1, "total_data": 1}},
    )
    result = get_vulnerability_action.run(
        GetVulnerabilityArguments(vulnerability_id="unix-anonymous-root-logins")
    )
    assert result["id"] == "unix-anonymous-root-logins"
    assert result["cvss_v3_score"] == 8.4


def test_get_vulnerability_empty_result(get_vulnerability_action, requests_mock):
    """When the vulnerability is not found, action must return empty dict."""
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/vulnerabilities",
        json={"data": [], "metadata": {"index": 0, "size": 1, "total_data": 0}},
    )
    result = get_vulnerability_action.run(
        GetVulnerabilityArguments(vulnerability_id="non-existent-vuln")
    )
    assert result == {}


def test_get_vulnerability_request_body(get_vulnerability_action, requests_mock):
    """Action must send the correct vulnKey filter in the request body."""
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/vulnerabilities",
        json={"data": [], "metadata": {}},
    )
    get_vulnerability_action.run(
        GetVulnerabilityArguments(vulnerability_id="my-vuln-key")
    )
    body = requests_mock.last_request.json()
    assert "vulnerability.vulnKey = 'my-vuln-key'" in body["vulnerability"]
    assert body["size"] == 1
