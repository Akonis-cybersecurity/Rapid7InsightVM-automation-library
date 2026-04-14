from typing import List, Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from .. import Rapid7InsightvmModule
from ..client import InsightVMClient


def _secret(val: object) -> str:
    return val.get_secret_value() if hasattr(val, "get_secret_value") else val  # type: ignore[return-value]


class SearchAssetsArguments(BaseModel):
    ip: Optional[str] = Field(None, description="Filter by exact IP address (e.g. '10.0.0.1')")
    host_name: Optional[str] = Field(None, description="Filter by host name (substring match)")
    tag: Optional[str] = Field(None, description="Filter by asset tag name")
    os_family: Optional[str] = Field(None, description="Filter by OS family (e.g. 'Windows', 'Linux')")
    severity_filter: Optional[str] = Field(
        None,
        description=(
            "Vulnerability severity filter using InsightVM Query Builder syntax "
            "(e.g. \"severity IN ['Critical', 'Severe']\")"
        ),
    )


class SearchAssetsAction(Action):
    module: Rapid7InsightvmModule

    def run(self, arguments: SearchAssetsArguments) -> List[dict]:
        client = InsightVMClient(
            api_key=_secret(self.module.configuration.api_key),
            base_url=self.module.configuration.base_url,
        )

        # Build the asset filter dynamically from provided arguments
        conditions = []
        if arguments.ip:
            conditions.append(f"ip_address = '{arguments.ip}'")
        if arguments.host_name:
            conditions.append(f"host_name CONTAINS '{arguments.host_name}'")
        if arguments.tag:
            conditions.append(f"tag.name = '{arguments.tag}'")
        if arguments.os_family:
            conditions.append(f"os.family CONTAINS '{arguments.os_family}'")

        body: dict = {"size": 500}

        if conditions:
            body["asset"] = " AND ".join(conditions)

        if arguments.severity_filter:
            body["vulnerability"] = arguments.severity_filter

        result = client.search_assets(body)
        return result.get("data", [])
