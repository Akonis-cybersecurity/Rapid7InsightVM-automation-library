from datetime import datetime, timezone
from typing import List, Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from .. import Rapid7InsightvmModule
from ..client import InsightVMClient


def _secret(val: object) -> str:
    return val.get_secret_value() if hasattr(val, "get_secret_value") else val  # type: ignore[return-value]


class GetRemediatedFindingsArguments(BaseModel):
    since: str = Field(
        ...,
        description=(
            "ISO 8601 datetime (e.g. '2024-01-15T00:00:00Z') — "
            "returns findings remediated since this point in time"
        ),
    )
    severity_filter: Optional[str] = Field(
        None,
        description=(
            "Vulnerability severity filter using InsightVM Query Builder syntax "
            "(e.g. \"severity IN ['Critical', 'Severe']\")"
        ),
    )


class GetRemediatedFindingsAction(Action):
    module: Rapid7InsightvmModule

    def run(self, arguments: GetRemediatedFindingsArguments) -> List[dict]:
        client = InsightVMClient(
            api_key=_secret(self.module.configuration.api_key),
            base_url=self.module.configuration.base_url,
        )

        # Normalise the since timestamp — ensure it has timezone info
        since = arguments.since
        if not since.endswith("Z") and "+" not in since and "-" not in since[10:]:
            since = since + "Z"

        now: str = datetime.now(timezone.utc).isoformat()

        all_remediated: List[dict] = []
        cursor: Optional[str] = None

        while True:
            body: dict = {
                "size": 500,
                "comparisonTime": since,
                "currentTime": now,
                "includeSame": False,
            }

            if arguments.severity_filter:
                body["vulnerability"] = arguments.severity_filter

            if cursor:
                body["cursor"] = cursor

            data = client.search_assets(body)
            assets = data.get("data", [])

            for asset in assets:
                remediated = asset.get("remediated") or []
                for finding in remediated:
                    # Attach the asset context to each finding for traceability
                    enriched = dict(finding)
                    enriched.setdefault("asset_id", asset.get("id"))
                    enriched.setdefault("asset_ip", asset.get("ip"))
                    enriched.setdefault("asset_host_name", asset.get("host_name"))
                    all_remediated.append(enriched)

            cursor = data.get("metadata", {}).get("cursor")
            if not cursor or not assets:
                break

        return all_remediated
