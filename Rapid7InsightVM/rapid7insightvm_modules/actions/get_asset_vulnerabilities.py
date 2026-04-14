from typing import List, Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from .. import Rapid7InsightvmModule
from ..client import InsightVMClient

DEFAULT_SEVERITY_FILTER = "severity IN ['Critical', 'Severe']"


def _secret(val: object) -> str:
    return val.get_secret_value() if hasattr(val, "get_secret_value") else val  # type: ignore[return-value]


class GetAssetVulnerabilitiesArguments(BaseModel):
    asset_id: str = Field(..., description="InsightVM asset identifier")
    severity_filter: str = Field(
        DEFAULT_SEVERITY_FILTER,
        description=(
            "Vulnerability severity filter using InsightVM Query Builder syntax "
            "(e.g. \"severity IN ['Critical', 'Severe']\")"
        ),
    )
    include_same: bool = Field(
        False,
        description="Include unchanged (same) vulnerabilities in addition to new and remediated ones",
    )


class GetAssetVulnerabilitiesAction(Action):
    module: Rapid7InsightvmModule

    def run(self, arguments: GetAssetVulnerabilitiesArguments) -> List[dict]:
        client = InsightVMClient(
            api_key=_secret(self.module.configuration.api_key),
            base_url=self.module.configuration.base_url,
        )

        all_findings: List[dict] = []
        cursor: Optional[str] = None

        while True:
            body: dict = {
                "size": 500,
                "asset": f"id = '{arguments.asset_id}'",
                "includeSame": arguments.include_same,
            }

            if arguments.severity_filter:
                body["vulnerability"] = arguments.severity_filter

            if cursor:
                body["cursor"] = cursor

            data = client.search_assets(body)
            assets = data.get("data", [])

            for asset in assets:
                # Collect new + remediated (and same if requested) findings
                findings = list(asset.get("new", []) or [])
                findings += list(asset.get("remediated", []) or [])
                if arguments.include_same:
                    findings += list(asset.get("same", []) or [])
                all_findings.extend(findings)

            cursor = data.get("metadata", {}).get("cursor")
            if not cursor or not assets:
                break

        return all_findings
