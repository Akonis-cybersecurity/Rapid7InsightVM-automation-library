from enum import Enum
from typing import List, Optional

from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from .. import Rapid7InsightvmModule
from ..client import InsightVMClient


def _secret(val: object) -> str:
    return val.get_secret_value() if hasattr(val, "get_secret_value") else val  # type: ignore[return-value]


class SeverityEnum(str, Enum):
    critical = "Critical"
    severe = "Severe"
    moderate = "Moderate"


class SearchVulnerabilitiesArguments(BaseModel):
    cve: Optional[str] = Field(None, description="Filter by CVE identifier (e.g. 'CVE-2024-1234')")
    severity: Optional[SeverityEnum] = Field(None, description="Filter by severity level")
    min_cvss_v3: Optional[float] = Field(None, description="Minimum CVSS v3 score (inclusive, 0.0–10.0)")
    vuln_key: Optional[str] = Field(
        None, description="Filter by vulnerability key (e.g. 'unix-anonymous-root-logins')"
    )


class SearchVulnerabilitiesAction(Action):
    module: Rapid7InsightvmModule

    def run(self, arguments: SearchVulnerabilitiesArguments) -> List[dict]:
        client = InsightVMClient(
            api_key=_secret(self.module.configuration.api_key),
            base_url=self.module.configuration.base_url,
        )

        # Build the vulnerability filter dynamically
        conditions = []
        if arguments.cve:
            conditions.append(f"vulnerability.cve = '{arguments.cve}'")
        if arguments.severity:
            conditions.append(f"severity = '{arguments.severity.value}'")
        if arguments.min_cvss_v3 is not None:
            conditions.append(f"cvss_v3_score >= {arguments.min_cvss_v3}")
        if arguments.vuln_key:
            conditions.append(f"vulnerability.vulnKey = '{arguments.vuln_key}'")

        body: dict = {"size": 500}
        if conditions:
            body["vulnerability"] = " AND ".join(conditions)

        result = client.search_vulnerabilities(body)
        return result.get("data", [])
