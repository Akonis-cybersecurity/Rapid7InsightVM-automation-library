from pydantic.v1 import BaseModel, Field
from sekoia_automation.action import Action

from .. import Rapid7InsightvmModule
from ..client import InsightVMClient


def _secret(val: object) -> str:
    return val.get_secret_value() if hasattr(val, "get_secret_value") else val  # type: ignore[return-value]


class GetAssetArguments(BaseModel):
    asset_id: str = Field(..., description="InsightVM asset identifier")


class GetAssetAction(Action):
    module: Rapid7InsightvmModule

    def run(self, arguments: GetAssetArguments) -> dict:
        client = InsightVMClient(
            api_key=_secret(self.module.configuration.api_key),
            base_url=self.module.configuration.base_url,
        )
        return client.get_asset(arguments.asset_id)
