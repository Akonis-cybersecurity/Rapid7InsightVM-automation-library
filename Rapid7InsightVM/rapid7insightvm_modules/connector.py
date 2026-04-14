import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic.v1 import Field
from sekoia_automation.connector import Connector, DefaultConnectorConfiguration
from sekoia_automation.storage import PersistentJSON

from . import Rapid7InsightvmModule
from .client import InsightVMClient

# Maximum number of vulnerability IDs to resolve in a single catalogue query
_ENRICH_BATCH_SIZE = 100


def _secret(val: object) -> str:
    """Return the plain-text value of a SecretStr or a bare str.

    The Sekoia SDK sometimes injects secrets via setattr(), bypassing pydantic
    validation — so a SecretStr field may arrive as a plain str at runtime.
    """
    return val.get_secret_value() if hasattr(val, "get_secret_value") else val  # type: ignore[return-value]


class InsightVMConnectorConfiguration(DefaultConnectorConfiguration):
    polling_interval: int = Field(5, description="Polling interval in minutes")
    page_size: int = Field(500, description="API page size (max 500)")
    severity_filter: str = Field(
        "severity IN ['Critical', 'Severe']",
        description="Vulnerability severity filter (leave empty to fetch all severities)",
    )
    include_same: bool = Field(False, description="Include unchanged vulnerabilities in each cycle")
    enrich_with_vuln_details: bool = Field(
        False,
        description=(
            "If enabled, unique vulnerability IDs found in new/remediated findings are resolved "
            "against the vulnerability catalogue and their cvss_v3_score and cves fields are "
            "injected into each finding before the event is pushed."
        ),
    )


class InsightVMConnector(Connector):
    module: Rapid7InsightvmModule
    configuration: InsightVMConnectorConfiguration

    def run(self) -> None:
        self.log(message="Starting Rapid7 InsightVM connector", level="info")
        try:
            if not self._client().validate():
                self.log(
                    message="API key validation failed — check that the key is an Organization Key "
                    "with sufficient permissions on the Rapid7 Insight Platform.",
                    level="error",
                )
        except Exception as exc:
            self.log_exception(exc, message="Could not reach the Rapid7 API during startup validation")

        while self.running:
            try:
                self._poll_cycle()
            except Exception as exc:
                self.log_exception(exc, message="Error during polling cycle")
            time.sleep(self.configuration.polling_interval * 60)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> InsightVMClient:
        return InsightVMClient(
            api_key=_secret(self.module.configuration.api_key),
            base_url=self.module.configuration.base_url,
        )

    def _fetch_vuln_details(self, client: InsightVMClient, vuln_ids: List[str]) -> Dict[str, dict]:
        """Resolve a list of vulnerability IDs against the catalogue.

        Returns a mapping of vulnerability_id -> {cvss_v3_score, cves}.
        Queries are issued in batches to stay within URL/body size limits.
        """
        lookup: Dict[str, dict] = {}
        for i in range(0, len(vuln_ids), _ENRICH_BATCH_SIZE):
            batch = vuln_ids[i : i + _ENRICH_BATCH_SIZE]
            ids_list = ", ".join(f"'{v}'" for v in batch)
            body = {
                "vulnerability": f"vulnerability.vulnKey IN [{ids_list}]",
                "size": _ENRICH_BATCH_SIZE,
            }
            try:
                result = client.search_vulnerabilities(body)
                for vuln in result.get("data", []):
                    vid = vuln.get("id") or vuln.get("vulnerability_id") or vuln.get("vulnKey")
                    if vid:
                        lookup[vid] = {
                            "cvss_v3_score": vuln.get("cvss_v3_score"),
                            "cves": vuln.get("cves"),
                        }
            except Exception as exc:
                self.log_exception(exc, message=f"Could not enrich vulnerability batch starting at index {i}")
        return lookup

    def _enrich_asset_findings(self, assets: List[dict], vuln_lookup: Dict[str, dict]) -> None:
        """Inject cvss_v3_score and cves from the catalogue into each finding in-place."""
        for asset in assets:
            for bucket in ("new", "remediated", "same"):
                for finding in asset.get(bucket) or []:
                    vid = finding.get("vulnerability_id")
                    if vid and vid in vuln_lookup:
                        details = vuln_lookup[vid]
                        if details.get("cvss_v3_score") is not None:
                            finding["cvss_v3_score"] = details["cvss_v3_score"]
                        if details.get("cves") is not None:
                            finding["cves"] = details["cves"]

    def _poll_cycle(self) -> None:
        with PersistentJSON("context.json") as ctx:
            last_poll: Optional[str] = ctx.get("assets_cursor")
            now: str = datetime.now(timezone.utc).isoformat()

            # Restore pagination cursor from a previous interrupted cycle
            page_cursor: Optional[str] = ctx.get("assets_cursor_page_token")

            client = self._client()
            total = 0

            while self.running:
                body: dict = {
                    "size": self.configuration.page_size,
                    "includeSame": self.configuration.include_same,
                }

                if last_poll:
                    # Ensure last_poll timestamp has timezone info
                    lp = last_poll
                    if not lp.endswith("Z") and "+" not in lp:
                        lp = lp + "Z"
                    body["asset"] = f"last_assessed_for_vulnerabilities > '{lp}'"
                    body["comparisonTime"] = lp
                    body["currentTime"] = now

                if self.configuration.severity_filter:
                    body["vulnerability"] = self.configuration.severity_filter

                if page_cursor:
                    body["cursor"] = page_cursor

                data = client.search_assets(body)
                assets = data.get("data", [])

                if assets and self.configuration.enrich_with_vuln_details:
                    # Collect all unique vulnerability IDs from new + remediated findings
                    vuln_ids = list(
                        {
                            finding["vulnerability_id"]
                            for asset in assets
                            for bucket in ("new", "remediated")
                            for finding in (asset.get(bucket) or [])
                            if finding.get("vulnerability_id")
                        }
                    )
                    if vuln_ids:
                        vuln_lookup = self._fetch_vuln_details(client, vuln_ids)
                        self._enrich_asset_findings(assets, vuln_lookup)

                if assets:
                    events = [json.dumps(asset) for asset in assets]
                    self.push_events_to_intakes(events=events)
                    total += len(events)

                next_cursor: Optional[str] = data.get("metadata", {}).get("cursor")

                if not next_cursor or not assets:
                    # Pagination complete — commit the time cursor and clear page token
                    ctx["assets_cursor"] = now
                    ctx["assets_cursor_page_token"] = None
                    break
                else:
                    # Mid-pagination: persist the page token so a restart can resume
                    page_cursor = next_cursor
                    ctx["assets_cursor_page_token"] = page_cursor

            self.log(message=f"Cycle complete: {total} assets pushed", level="info")
