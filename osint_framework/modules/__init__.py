from .mod_github import ModuleGitHub
from .mod_whois import ModuleWHOIS
from .mod_dns import ModuleDNS
from .mod_ip import ModuleIP
from .mod_breach import ModuleBreach
from .mod_reddit import ModuleReddit
from .mod_social import ModuleSocial
from .mod_phone import ModulePhone
from .mod_web import ModuleWeb
from .mod_people import ModulePeople
from .mod_email import ModuleEmail

ALL_MODULES = [
    ModuleGitHub,
    ModuleWHOIS,
    ModuleDNS,
    ModuleIP,
    ModuleBreach,
    ModuleReddit,
    ModuleSocial,
    ModulePhone,
    ModuleWeb,
    ModulePeople,
    ModuleEmail,
]

def get_modules_for(target_type):
    return [M() for M in ALL_MODULES if target_type in M.target_types]
