from typing import Any

from management.mgmtsdk_v2_1.entities.exclusion import Exclusion
from pydantic.v1 import BaseModel

from sentinelone_module.base import SentinelOneAction


# NOTE: For some reason, official SDK doesn't contain SHA-256 in this data structure
class ExclusionWithSHA256(Exclusion):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.sha256Value: str | None = kwargs.get("sha256Value", None)


class CreateBlocklistItemActionArguments(BaseModel):
    os_type: str  # osType "OS type": ["linux", "macos", "windows", "windows_legacy"]
    sha_1: str | None = None  # SHA1 of the file to add to the blocklist
    sha_256: str | None = None  # SHA256 of the file to add to the blocklist

    source: str | None = None  # Source
    description: str | None = None  # Description

    filter_tenant_scope: bool = False
    filter_account_ids: list[str] | None = None
    filter_site_ids: list[str] | None = None
    filter_group_ids: list[str] | None = None


class CreateBlocklistItemAction(SentinelOneAction):
    name = "Block SHA-1 and SHA-256"
    description = "Create a blocklist item for a SHA1 or SHA256 hash or both"

    @staticmethod
    def check_filters(arguments: CreateBlocklistItemActionArguments) -> None:
        # Make sure only 1 filter is present
        args_check = False
        args_check ^= arguments.filter_tenant_scope
        args_check ^= arguments.filter_account_ids is not None
        args_check ^= arguments.filter_site_ids is not None
        args_check ^= arguments.filter_group_ids is not None
        if not any(
            (
                arguments.filter_site_ids,
                arguments.filter_group_ids,
                arguments.filter_account_ids,
                arguments.filter_tenant_scope,
            )
        ):
            raise ValueError("Please provide a filter")

        if not args_check:
            raise ValueError("Only one filter should be present")

    def run(self, arguments: CreateBlocklistItemActionArguments) -> Any:
        self.check_filters(arguments)

        payload = ExclusionWithSHA256(
            type="black_hash",
            osType=arguments.os_type,
            value=arguments.sha_1,
            sha256Value=arguments.sha_256,
            source=arguments.source,
        )

        params: dict[str, bool | list[str]] = {}

        if arguments.filter_tenant_scope:
            params["tenant"] = True

        elif arguments.filter_account_ids:
            params["accountIds"] = arguments.filter_account_ids

        elif arguments.filter_site_ids:
            params["siteIds"] = arguments.filter_site_ids

        elif arguments.filter_group_ids:
            params["groupIds"] = arguments.filter_group_ids

        elif arguments.filter_site_ids:
            params["siteIds"] = arguments.filter_site_ids

        result = self.client.exclusions.create_black(exclusion=payload, **params)
        return result.json
