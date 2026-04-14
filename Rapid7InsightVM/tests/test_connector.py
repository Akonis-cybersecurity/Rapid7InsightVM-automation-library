import json
from unittest.mock import MagicMock, patch

import pytest

from rapid7insightvm_modules.connector import InsightVMConnector

BASE_URL = "https://us.api.insight.rapid7.com"


def _asset(idx: int) -> dict:
    return {
        "id": f"asset-{idx}",
        "ip": f"10.0.0.{idx}",
        "host_name": f"host-{idx}.example.com",
        "risk_score": 1000 * idx,
        "new": [{"vulnerability_id": f"vuln-{idx}", "status": "VULNERABLE_EXPL"}],
        "remediated": [],
        "same": [],
    }


# ---------------------------------------------------------------------------
# _poll_cycle — single page
# ---------------------------------------------------------------------------

def test_poll_cycle_single_page(connector, requests_mock):
    assets = [_asset(i) for i in range(3)]
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/assets",
        json={"data": assets, "metadata": {"cursor": None}},
    )

    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()

    connector.push_events_to_intakes.assert_called_once()
    pushed = connector.push_events_to_intakes.call_args[1]["events"]
    assert len(pushed) == 3
    # Each item must be a JSON string
    for item in pushed:
        assert isinstance(item, str)
        parsed = json.loads(item)
        assert "id" in parsed


# ---------------------------------------------------------------------------
# _poll_cycle — multi-page pagination
# ---------------------------------------------------------------------------

def test_poll_cycle_two_pages(connector, requests_mock):
    page1 = [_asset(i) for i in range(5)]
    page2 = [_asset(i) for i in range(5, 8)]

    call_count = {"n": 0}

    def asset_handler(request, context):
        call_count["n"] += 1
        body = request.json()
        if body.get("cursor") == "page2-token":
            return {"data": page2, "metadata": {"cursor": None}}
        return {"data": page1, "metadata": {"cursor": "page2-token"}}

    requests_mock.post(f"{BASE_URL}/vm/v4/integration/assets", json=asset_handler)

    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()

    assert call_count["n"] == 2
    all_pushed = []
    for call in connector.push_events_to_intakes.call_args_list:
        all_pushed.extend(call[1]["events"])
    assert len(all_pushed) == 8


# ---------------------------------------------------------------------------
# _poll_cycle — delta filter applied on second run
# ---------------------------------------------------------------------------

def test_poll_cycle_delta_filter_on_second_run(connector, requests_mock, data_storage):
    """Second cycle must include last_assessed_for_vulnerabilities filter."""
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/assets",
        json={"data": [_asset(1)], "metadata": {"cursor": None}},
    )
    connector.push_events_to_intakes = MagicMock()

    # First cycle — no filter
    connector._poll_cycle()
    first_body = requests_mock.last_request.json()
    assert "asset" not in first_body

    # Second cycle — delta filter must be present
    connector._poll_cycle()
    second_body = requests_mock.last_request.json()
    assert "last_assessed_for_vulnerabilities" in second_body.get("asset", "")
    assert "comparisonTime" in second_body
    assert "currentTime" in second_body


# ---------------------------------------------------------------------------
# _poll_cycle — empty response stops pagination
# ---------------------------------------------------------------------------

def test_poll_cycle_empty_response(connector, requests_mock):
    requests_mock.post(
        f"{BASE_URL}/vm/v4/integration/assets",
        json={"data": [], "metadata": {"cursor": "some-cursor"}},
    )
    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()
    connector.push_events_to_intakes.assert_not_called()


# ---------------------------------------------------------------------------
# _poll_cycle — respects self.running = False mid-pagination
# ---------------------------------------------------------------------------

def test_poll_cycle_stops_when_not_running(connector, requests_mock):
    call_count = {"n": 0}

    def asset_handler(request, context):
        call_count["n"] += 1
        connector._running = False  # simulate stop signal after first page
        return {"data": [_asset(0)], "metadata": {"cursor": "page2-token"}}

    requests_mock.post(f"{BASE_URL}/vm/v4/integration/assets", json=asset_handler)
    connector.push_events_to_intakes = MagicMock()
    connector._poll_cycle()

    # Must have stopped after 1 page due to running=False
    assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# _poll_cycle — API exception is logged and propagated
# ---------------------------------------------------------------------------

def test_poll_cycle_api_error_propagates(connector, requests_mock):
    requests_mock.post(f"{BASE_URL}/vm/v4/integration/assets", status_code=500)
    import rapid7insightvm_modules.client as client_mod
    original = client_mod.RETRY_DELAYS
    client_mod.RETRY_DELAYS = []
    connector.push_events_to_intakes = MagicMock()
    try:
        with pytest.raises(Exception):
            connector._poll_cycle()
    finally:
        client_mod.RETRY_DELAYS = original


# ---------------------------------------------------------------------------
# _client — secret helper
# ---------------------------------------------------------------------------

def test_client_secret_helper(connector):
    """_client() must work whether api_key is SecretStr or plain str."""
    from rapid7insightvm_modules.connector import _secret
    from pydantic.v1 import SecretStr

    assert _secret(SecretStr("plain")) == "plain"
    assert _secret("plain") == "plain"
