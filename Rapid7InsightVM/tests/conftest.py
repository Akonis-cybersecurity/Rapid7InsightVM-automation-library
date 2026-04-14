from shutil import rmtree
from tempfile import mkdtemp

import pytest
from sekoia_automation import constants
from sekoia_automation.storage import get_data_path

from rapid7insightvm_modules import Rapid7InsightvmModule
from rapid7insightvm_modules.models import Rapid7InsightvmModuleConfiguration
from rapid7insightvm_modules.connector import InsightVMConnector, InsightVMConnectorConfiguration
from rapid7insightvm_modules.actions.get_asset import GetAssetAction
from rapid7insightvm_modules.actions.get_vulnerability import GetVulnerabilityAction


@pytest.fixture
def data_storage():
    original_storage = constants.DATA_STORAGE
    # Save the path in a local variable — the SDK (Trigger.__init__) may overwrite
    # constants.DATA_STORAGE internally, so we must not rely on it at teardown time.
    tmpdir = mkdtemp()
    constants.DATA_STORAGE = tmpdir

    # get_data_path() is lru_cached — clear it so this test's tmpdir is picked up
    get_data_path.cache_clear()

    yield tmpdir

    rmtree(tmpdir, ignore_errors=True)
    constants.DATA_STORAGE = original_storage
    get_data_path.cache_clear()


@pytest.fixture
def module():
    m = Rapid7InsightvmModule()
    m.configuration = Rapid7InsightvmModuleConfiguration(
        api_key="test-api-key",
        base_url="https://us.api.insight.rapid7.com",
    )
    return m


@pytest.fixture
def connector(module, data_storage):
    conn = InsightVMConnector(data_path=data_storage)
    conn.module = module
    conn.configuration = InsightVMConnectorConfiguration(
        intake_key="test-intake-key",
        polling_interval=1,
        page_size=500,
        severity_filter="severity IN ['Critical', 'Severe']",
        include_same=False,
    )
    return conn


@pytest.fixture
def get_asset_action(module):
    action = GetAssetAction()
    action.module = module
    return action


@pytest.fixture
def get_vulnerability_action(module):
    action = GetVulnerabilityAction()
    action.module = module
    return action
