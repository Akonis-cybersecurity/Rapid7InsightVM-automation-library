"""Tests for the four new InsightVM actions and related client/connector improvements."""
import pytest

from rapid7insightvm_modules.actions.search_assets import SearchAssetsAction, SearchAssetsArguments
from rapid7insightvm_modules.actions.get_asset_vulnerabilities import (
    GetAssetVulnerabilitiesAction,
    GetAssetVulnerabilitiesArguments,
)
from rapid7insightvm_modules.actions.search_vulnerabilities import (
    SearchVulnerabilitiesAction,
    SearchVulnerabilitiesArguments,
    SeverityEnum,
)
from rapid7insightvm_modules.actions.get_remediated_findings import (
    GetRemediatedFindingsAction,
    GetRemediatedFindingsArguments,
)

BASE_URL = "https://us.api.insight.rapid7.com"
ASSETS_URL = f"{BASE_URL}/vm/v4/integration/assets"
VULNS_URL = f"{BASE_URL}/vm/v4/integration/vulnerabilities"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def search_assets_action(module):
    action = SearchAssetsAction()
    action.module = module
    return action


@pytest.fixture
def get_asset_vulns_action(module):
    action = GetAssetVulnerabilitiesAction()
    action.module = module
    return action


@pytest.fixture
def search_vulns_action(module):
    action = SearchVulnerabilitiesAction()
    action.module = module
    return action


@pytest.fixture
def get_remediated_action(module):
    action = GetRemediatedFindingsAction()
    action.module = module
    return action


def _asset(idx: int, new_count: int = 1, remediated_count: int = 0) -> dict:
    return {
        "id": f"asset-{idx}",
        "ip": f"10.0.0.{idx}",
        "host_name": f"host-{idx}.example.com",
        "risk_score": 1000 * idx,
        "new": [{"vulnerability_id": f"vuln-new-{idx}-{j}", "status": "VULNERABLE_EXPL"} for j in range(new_count)],
        "remediated": [{"vulnerability_id": f"vuln-rem-{idx}-{j}", "status": "REMEDIATED"} for j in range(remediated_count)],
        "same": [],
    }


# ===========================================================================
# SearchAssetsAction
# ===========================================================================


class TestSearchAssetsAction:
    def test_happy_path_returns_assets(self, search_assets_action, requests_mock):
        """Returns assets from the first page."""
        assets = [_asset(i) for i in range(3)]
        requests_mock.post(ASSETS_URL, json={"data": assets, "metadata": {"cursor": None}})

        result = search_assets_action.run(SearchAssetsArguments())
        assert len(result) == 3
        assert result[0]["id"] == "asset-0"

    def test_empty_result(self, search_assets_action, requests_mock):
        """Returns empty list when no assets match."""
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        result = search_assets_action.run(SearchAssetsArguments())
        assert result == []

    def test_filter_by_ip(self, search_assets_action, requests_mock):
        """IP filter is sent in the asset query."""
        requests_mock.post(ASSETS_URL, json={"data": [_asset(1)], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments(ip="10.0.0.1"))
        body = requests_mock.last_request.json()
        assert "ip_address = '10.0.0.1'" in body["asset"]

    def test_filter_by_host_name(self, search_assets_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments(host_name="prod-server"))
        body = requests_mock.last_request.json()
        assert "host_name CONTAINS 'prod-server'" in body["asset"]

    def test_filter_by_tag(self, search_assets_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments(tag="production"))
        body = requests_mock.last_request.json()
        assert "tag.name = 'production'" in body["asset"]

    def test_filter_by_os_family(self, search_assets_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments(os_family="Windows"))
        body = requests_mock.last_request.json()
        assert "os.family CONTAINS 'Windows'" in body["asset"]

    def test_multiple_filters_combined_with_and(self, search_assets_action, requests_mock):
        """Multiple filters must be joined with AND."""
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments(ip="10.0.0.1", tag="prod"))
        body = requests_mock.last_request.json()
        assert " AND " in body["asset"]
        assert "ip_address = '10.0.0.1'" in body["asset"]
        assert "tag.name = 'prod'" in body["asset"]

    def test_no_filter_omits_asset_key(self, search_assets_action, requests_mock):
        """When no filter is specified the asset key must be absent from the body."""
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments())
        body = requests_mock.last_request.json()
        assert "asset" not in body

    def test_severity_filter_sent(self, search_assets_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments(severity_filter="severity IN ['Critical']"))
        body = requests_mock.last_request.json()
        assert body["vulnerability"] == "severity IN ['Critical']"

    def test_page_size_is_500(self, search_assets_action, requests_mock):
        """Action always requests 500 assets per page."""
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {}})
        search_assets_action.run(SearchAssetsArguments())
        assert requests_mock.last_request.json()["size"] == 500

    def test_returns_only_first_page(self, search_assets_action, requests_mock):
        """Action stops after the first page even if a cursor is present."""
        assets = [_asset(i) for i in range(5)]
        requests_mock.post(ASSETS_URL, json={"data": assets, "metadata": {"cursor": "page2-token"}})
        result = search_assets_action.run(SearchAssetsArguments())
        # Only one POST was made
        assert requests_mock.call_count == 1
        assert len(result) == 5


# ===========================================================================
# GetAssetVulnerabilitiesAction
# ===========================================================================


class TestGetAssetVulnerabilitiesAction:
    def test_happy_path_returns_findings(self, get_asset_vulns_action, requests_mock):
        asset = _asset(1, new_count=2, remediated_count=1)
        requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})

        result = get_asset_vulns_action.run(GetAssetVulnerabilitiesArguments(asset_id="asset-1"))
        # 2 new + 1 remediated = 3 findings
        assert len(result) == 3

    def test_asset_id_filter_in_body(self, get_asset_vulns_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        get_asset_vulns_action.run(GetAssetVulnerabilitiesArguments(asset_id="my-asset-42"))
        body = requests_mock.last_request.json()
        assert "id = 'my-asset-42'" in body["asset"]

    def test_default_severity_filter_applied(self, get_asset_vulns_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        get_asset_vulns_action.run(GetAssetVulnerabilitiesArguments(asset_id="a1"))
        body = requests_mock.last_request.json()
        assert "severity" in body.get("vulnerability", "")

    def test_no_results_returns_empty_list(self, get_asset_vulns_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        result = get_asset_vulns_action.run(GetAssetVulnerabilitiesArguments(asset_id="unknown"))
        assert result == []

    def test_pagination_exhausts_all_pages(self, get_asset_vulns_action, requests_mock):
        """Action must follow cursors and accumulate findings from all pages."""
        asset_page1 = _asset(1, new_count=3)
        asset_page2 = _asset(2, new_count=2)

        call_count = {"n": 0}

        def handler(request, context):
            call_count["n"] += 1
            body = request.json()
            if body.get("cursor") == "page2":
                return {"data": [asset_page2], "metadata": {"cursor": None}}
            return {"data": [asset_page1], "metadata": {"cursor": "page2"}}

        requests_mock.post(ASSETS_URL, json=handler)
        result = get_asset_vulns_action.run(GetAssetVulnerabilitiesArguments(asset_id="a1"))

        assert call_count["n"] == 2
        # 3 new from page1 + 2 new from page2 = 5 total
        assert len(result) == 5

    def test_include_same_false_excludes_same_findings(self, get_asset_vulns_action, requests_mock):
        asset = {
            "id": "asset-1",
            "new": [{"vulnerability_id": "v-new"}],
            "remediated": [{"vulnerability_id": "v-rem"}],
            "same": [{"vulnerability_id": "v-same"}],
        }
        requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})
        result = get_asset_vulns_action.run(
            GetAssetVulnerabilitiesArguments(asset_id="asset-1", include_same=False)
        )
        ids = [f["vulnerability_id"] for f in result]
        assert "v-new" in ids
        assert "v-rem" in ids
        assert "v-same" not in ids

    def test_include_same_true_includes_same_findings(self, get_asset_vulns_action, requests_mock):
        asset = {
            "id": "asset-1",
            "new": [{"vulnerability_id": "v-new"}],
            "remediated": [],
            "same": [{"vulnerability_id": "v-same"}],
        }
        requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})
        result = get_asset_vulns_action.run(
            GetAssetVulnerabilitiesArguments(asset_id="asset-1", include_same=True)
        )
        ids = [f["vulnerability_id"] for f in result]
        assert "v-new" in ids
        assert "v-same" in ids


# ===========================================================================
# SearchVulnerabilitiesAction
# ===========================================================================


class TestSearchVulnerabilitiesAction:
    def test_happy_path_returns_vulns(self, search_vulns_action, requests_mock):
        vulns = [
            {"id": "vuln-1", "severity": "critical", "cvss_v3_score": 9.8},
            {"id": "vuln-2", "severity": "severe", "cvss_v3_score": 7.5},
        ]
        requests_mock.post(VULNS_URL, json={"data": vulns, "metadata": {}})
        result = search_vulns_action.run(SearchVulnerabilitiesArguments())
        assert len(result) == 2

    def test_empty_result(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        result = search_vulns_action.run(SearchVulnerabilitiesArguments())
        assert result == []

    def test_no_filter_omits_vulnerability_key(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(SearchVulnerabilitiesArguments())
        body = requests_mock.last_request.json()
        assert "vulnerability" not in body

    def test_filter_by_cve(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(SearchVulnerabilitiesArguments(cve="CVE-2024-1234"))
        body = requests_mock.last_request.json()
        assert "vulnerability.cve = 'CVE-2024-1234'" in body["vulnerability"]

    def test_filter_by_severity(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(SearchVulnerabilitiesArguments(severity=SeverityEnum.critical))
        body = requests_mock.last_request.json()
        assert "severity = 'Critical'" in body["vulnerability"]

    def test_filter_by_min_cvss(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(SearchVulnerabilitiesArguments(min_cvss_v3=7.0))
        body = requests_mock.last_request.json()
        assert "cvss_v3_score >= 7.0" in body["vulnerability"]

    def test_filter_by_vuln_key(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(SearchVulnerabilitiesArguments(vuln_key="unix-anon-root"))
        body = requests_mock.last_request.json()
        assert "vulnerability.vulnKey = 'unix-anon-root'" in body["vulnerability"]

    def test_multiple_filters_joined_with_and(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(
            SearchVulnerabilitiesArguments(severity=SeverityEnum.critical, min_cvss_v3=9.0)
        )
        body = requests_mock.last_request.json()
        assert " AND " in body["vulnerability"]
        assert "severity = 'Critical'" in body["vulnerability"]
        assert "cvss_v3_score >= 9.0" in body["vulnerability"]

    def test_page_size_is_500(self, search_vulns_action, requests_mock):
        requests_mock.post(VULNS_URL, json={"data": [], "metadata": {}})
        search_vulns_action.run(SearchVulnerabilitiesArguments())
        assert requests_mock.last_request.json()["size"] == 500


# ===========================================================================
# GetRemediatedFindingsAction
# ===========================================================================


class TestGetRemediatedFindingsAction:
    def test_happy_path_returns_remediated_only(self, get_remediated_action, requests_mock):
        assets = [_asset(i, new_count=1, remediated_count=2) for i in range(2)]
        requests_mock.post(ASSETS_URL, json={"data": assets, "metadata": {"cursor": None}})

        result = get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        # 2 assets × 2 remediated findings each = 4
        assert len(result) == 4

    def test_excludes_new_findings(self, get_remediated_action, requests_mock):
        asset = _asset(1, new_count=3, remediated_count=1)
        requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})

        result = get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        assert len(result) == 1
        assert result[0]["vulnerability_id"] == "vuln-rem-1-0"

    def test_asset_context_injected(self, get_remediated_action, requests_mock):
        """Each finding must carry the asset_id, asset_ip, and asset_host_name."""
        asset = {
            "id": "asset-xyz",
            "ip": "192.168.1.10",
            "host_name": "myhost.example.com",
            "new": [],
            "remediated": [{"vulnerability_id": "v1"}],
            "same": [],
        }
        requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})

        result = get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        assert result[0]["asset_id"] == "asset-xyz"
        assert result[0]["asset_ip"] == "192.168.1.10"
        assert result[0]["asset_host_name"] == "myhost.example.com"

    def test_empty_result(self, get_remediated_action, requests_mock):
        """Returns empty list when no assets have remediated findings."""
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        result = get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        assert result == []

    def test_assets_with_no_remediated_findings(self, get_remediated_action, requests_mock):
        """Assets that have only new findings contribute nothing to the result."""
        asset = _asset(1, new_count=5, remediated_count=0)
        requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})

        result = get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        assert result == []

    def test_pagination_exhausts_all_pages(self, get_remediated_action, requests_mock):
        page1 = [_asset(i, new_count=0, remediated_count=1) for i in range(3)]
        page2 = [_asset(i + 10, new_count=0, remediated_count=2) for i in range(2)]

        call_count = {"n": 0}

        def handler(request, context):
            call_count["n"] += 1
            body = request.json()
            if body.get("cursor") == "page2":
                return {"data": page2, "metadata": {"cursor": None}}
            return {"data": page1, "metadata": {"cursor": "page2"}}

        requests_mock.post(ASSETS_URL, json=handler)
        result = get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        assert call_count["n"] == 2
        # 3×1 + 2×2 = 7 remediated findings total
        assert len(result) == 7

    def test_comparison_time_and_current_time_sent(self, get_remediated_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-06-01T12:00:00Z")
        )
        body = requests_mock.last_request.json()
        assert body["comparisonTime"] == "2024-06-01T12:00:00Z"
        assert "currentTime" in body

    def test_severity_filter_forwarded(self, get_remediated_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        get_remediated_action.run(
            GetRemediatedFindingsArguments(
                since="2024-01-01T00:00:00Z",
                severity_filter="severity IN ['Critical']",
            )
        )
        body = requests_mock.last_request.json()
        assert body["vulnerability"] == "severity IN ['Critical']"

    def test_no_severity_filter_omits_vulnerability_key(self, get_remediated_action, requests_mock):
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        body = requests_mock.last_request.json()
        assert "vulnerability" not in body

    def test_include_same_is_false(self, get_remediated_action, requests_mock):
        """includeSame must always be False to avoid bloating the response."""
        requests_mock.post(ASSETS_URL, json={"data": [], "metadata": {"cursor": None}})
        get_remediated_action.run(
            GetRemediatedFindingsArguments(since="2024-01-01T00:00:00Z")
        )
        body = requests_mock.last_request.json()
        assert body["includeSame"] is False


# ===========================================================================
# client.py — Retry-After header handling
# ===========================================================================


class TestRetryAfterHeader:
    def test_retry_after_header_used_as_sleep_duration(self, requests_mock, monkeypatch):
        """When the API returns a 429 with Retry-After: 5, the client must sleep for 5s."""
        from rapid7insightvm_modules.client import InsightVMClient

        sleep_calls = []
        monkeypatch.setattr("rapid7insightvm_modules.client.time.sleep", lambda s: sleep_calls.append(s))

        # First call returns 429 with Retry-After: 5, second succeeds
        responses = [
            {"status_code": 429, "headers": {"Retry-After": "5"}, "json": {}},
        ]
        call_count = {"n": 0}

        def handler(request, context):
            call_count["n"] += 1
            if call_count["n"] == 1:
                context.status_code = 429
                context.headers["Retry-After"] = "5"
                return {}
            context.status_code = 200
            return {"data": [], "metadata": {}}

        requests_mock.post(ASSETS_URL, json=handler)

        import rapid7insightvm_modules.client as client_mod
        original = client_mod.RETRY_DELAYS
        client_mod.RETRY_DELAYS = [60]  # fallback would be 60s
        try:
            client = InsightVMClient(api_key="k", base_url=BASE_URL)
            client.search_assets({})
        finally:
            client_mod.RETRY_DELAYS = original

        # Sleep must have been called with 5 (from Retry-After), not 60 (fallback)
        assert 5 in sleep_calls
        assert 60 not in sleep_calls

    def test_fallback_to_progressive_backoff_when_no_header(self, requests_mock, monkeypatch):
        """When 429 has no Retry-After header, fall back to RETRY_DELAYS."""
        from rapid7insightvm_modules.client import InsightVMClient

        sleep_calls = []
        monkeypatch.setattr("rapid7insightvm_modules.client.time.sleep", lambda s: sleep_calls.append(s))

        call_count = {"n": 0}

        def handler(request, context):
            call_count["n"] += 1
            if call_count["n"] == 1:
                context.status_code = 429
                return {}
            context.status_code = 200
            return {"data": [], "metadata": {}}

        requests_mock.post(ASSETS_URL, json=handler)

        import rapid7insightvm_modules.client as client_mod
        original = client_mod.RETRY_DELAYS
        client_mod.RETRY_DELAYS = [42]
        try:
            client = InsightVMClient(api_key="k", base_url=BASE_URL)
            client.search_assets({})
        finally:
            client_mod.RETRY_DELAYS = original

        assert 42 in sleep_calls


# ===========================================================================
# connector.py — enrich_with_vuln_details
# Kept as standalone functions (not a class) to avoid shared constants.DATA_STORAGE
# state between methods — matches the pattern in test_connector.py.
# ===========================================================================


def test_enrichment_injects_cvss_and_cves(connector, requests_mock):
    """When enrich_with_vuln_details=True, findings get cvss_v3_score and cves."""
    import json as _json
    from unittest.mock import MagicMock

    connector.configuration.enrich_with_vuln_details = True

    asset = {
        "id": "asset-1",
        "ip": "10.0.0.1",
        "new": [{"vulnerability_id": "vuln-abc"}],
        "remediated": [],
        "same": [],
    }
    vuln_details = {
        "data": [{"id": "vuln-abc", "cvss_v3_score": 9.8, "cves": "CVE-2024-0001"}],
        "metadata": {},
    }

    requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})
    requests_mock.post(VULNS_URL, json=vuln_details)

    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()

    connector.push_events_to_intakes.assert_called_once()
    pushed_event = _json.loads(connector.push_events_to_intakes.call_args[1]["events"][0])
    finding = pushed_event["new"][0]
    assert finding["cvss_v3_score"] == 9.8
    assert finding["cves"] == "CVE-2024-0001"


def test_no_enrichment_when_flag_false(connector, requests_mock):
    """When enrich_with_vuln_details=False, vulnerability endpoint is never called."""
    from unittest.mock import MagicMock

    connector.configuration.enrich_with_vuln_details = False

    asset = _asset(1, new_count=2)
    requests_mock.post(ASSETS_URL, json={"data": [asset], "metadata": {"cursor": None}})

    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()

    # No call to the vulnerabilities endpoint
    for req in requests_mock.request_history:
        assert VULNS_URL not in req.url


def test_enrichment_deduplicates_vuln_ids(connector, requests_mock):
    """Same vulnerability_id appearing in multiple assets results in a single lookup."""
    from unittest.mock import MagicMock

    connector.configuration.enrich_with_vuln_details = True

    assets = [
        {
            "id": f"asset-{i}",
            "new": [{"vulnerability_id": "shared-vuln"}],
            "remediated": [],
            "same": [],
        }
        for i in range(3)
    ]
    requests_mock.post(ASSETS_URL, json={"data": assets, "metadata": {"cursor": None}})
    requests_mock.post(
        VULNS_URL,
        json={"data": [{"id": "shared-vuln", "cvss_v3_score": 7.5, "cves": None}], "metadata": {}},
    )

    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()

    # Only one call to the vulnerabilities endpoint (deduplicated)
    vuln_calls = [r for r in requests_mock.request_history if VULNS_URL in r.url]
    assert len(vuln_calls) == 1
    body = vuln_calls[0].json()
    # The IN filter must contain the ID exactly once
    assert body["vulnerability"].count("shared-vuln") == 1
