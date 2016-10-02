#! /usr/bin/python
import os

# ------------ General configuration ------------
# VOLATILITYBOT_HOME = '/Users/Martin/Projects/volatilitybot'
VOLATILITYBOT_HOME = '/home/Projects/volatilitybot/'
STORE_PATH = os.path.join(VOLATILITYBOT_HOME, 'Store')
DB_ENGINE = 'sqlite:///' + os.path.join(STORE_PATH, 'db.sqlite3')
LOG_PATH = '/tmp'
VOLATILITY_PATH = '/usr/local/bin/vol.py'
ACTIVE_MACHINE_TYPE = 'VMWARE'

# If you run into problems, and machines get stuck - disable threading in order to see what error you are getting
ENABLE_THREADING = True

# ------------ Agent configuration ------------
# Agent ket is used to verify no unauthorized executables are sent from server to agent
AGENT_KEY = 'ZZ4UNX4MGVSSCQ920O5CFCXR4UOYZ0S1UW70CLF9BC83E1VHA9W9MX0APTQ0WV0G'
AGENT_CHALLENGE_RESPONSE_KEY = 'E1P9YK366A6C7OPJOFQDGQAD839Y6LIC1LU6HGCBBUBD90Q4CK4XD2OH0A1PZGNP'
AGENT_PORT = '8000'

# Code Extractors configuration
CODE_EXTRACTORS = ['malfind', 'modscan', 'procdump']

# ------------ Post processors configuration ------------

# Path to yara rule file, the file included in this package contains rules from http://yararules.com/
YARA_FILE_PATH = os.path.join(VOLATILITYBOT_HOME,'conf','yara_rules.yar')

# Path to semantic yara rules
SEMANTIC_YARA_RULES_PATH = os.path.join(VOLATILITYBOT_HOME,'conf','Semantic_Rules.json')

# Agent sleep time before pausing and analyzing memory
DEFAULT_SLEEP_TIME = 60

# ------------ VMWARE configuration ------------

# The path
VMRUN_PATH = '/Applications/VMware\ Fusion.app/Contents/Library/vmrun'

MACHINE_INDEX = {
    'MWA7': {'is_64bit': True, 'vmx_path': r'/Users/Martin/Documents/Virtual Machines/MWA7/MWA7.vmwarevm/MWA7.vmx',
             'snapshot_name': 'volatilitybot', 'ip_address': '192.168.202.242',
             'memory_profile': 'Win7SP0x64', 'active': True},
    'MWAXP': {'is_64bit': False, 'vmx_path': r'/Users/Martin/Documents/Virtual Machines/MWA7/MWAXP.vmwarevm/MWAXP.vmx',
              'snapshot_name': 'VolatilityBot',
              'ip_address': '1.2.3.6', 'memory_profile': 'WinXPSP2x86', 'active': False}
}


# ------------ Heuristics configuration ------------

# Names of exploitable processes, in lowercase (Heuristics will normalize all names to lower case)
EXPLOITABLE_PROCESS_NAMES = ['iexplore.exe', 'chrome.exe', 'firefox.exe']
