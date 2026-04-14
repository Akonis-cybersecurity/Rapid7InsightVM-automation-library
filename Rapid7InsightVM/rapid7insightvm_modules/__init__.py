from sekoia_automation.module import Module
from rapid7insightvm_modules.models import Rapid7InsightvmModuleConfiguration


class Rapid7InsightvmModule(Module):
    configuration: Rapid7InsightvmModuleConfiguration
