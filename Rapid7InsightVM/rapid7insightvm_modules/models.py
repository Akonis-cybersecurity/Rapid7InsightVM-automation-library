from pydantic.v1 import BaseModel, Field, SecretStr


class Rapid7InsightvmModuleConfiguration(BaseModel):
    api_key: SecretStr = Field(..., description="Rapid7 Organization API Key")
    base_url: str = Field(
        "https://us.api.insight.rapid7.com",
        description="Rapid7 Insight Platform base URL (e.g. https://eu.api.insight.rapid7.com)",
    )
