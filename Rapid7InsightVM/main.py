from rapid7insightvm_modules import Rapid7InsightvmModule
from rapid7insightvm_modules.connector import InsightVMConnector
from rapid7insightvm_modules.actions.get_asset import GetAssetAction
from rapid7insightvm_modules.actions.get_vulnerability import GetVulnerabilityAction
from rapid7insightvm_modules.actions.search_assets import SearchAssetsAction
from rapid7insightvm_modules.actions.get_asset_vulnerabilities import GetAssetVulnerabilitiesAction
from rapid7insightvm_modules.actions.search_vulnerabilities import SearchVulnerabilitiesAction
from rapid7insightvm_modules.actions.get_remediated_findings import GetRemediatedFindingsAction

if __name__ == "__main__":
    module = Rapid7InsightvmModule()
    module.register(InsightVMConnector, "pull-insightvm-assets-vulns")
    module.register(GetAssetAction, "get-insightvm-asset")
    module.register(GetVulnerabilityAction, "get-insightvm-vulnerability")
    module.register(SearchAssetsAction, "search-insightvm-assets")
    module.register(GetAssetVulnerabilitiesAction, "get-insightvm-asset-vulnerabilities")
    module.register(SearchVulnerabilitiesAction, "search-insightvm-vulnerabilities")
    module.register(GetRemediatedFindingsAction, "get-insightvm-remediated-findings")
    module.run()
