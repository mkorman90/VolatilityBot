import json
import os
import pytest
import shutil

from volatilitybot.lib.common.utils import calc_sha256
from volatilitybot.lib.core.memory import MemoryDump
from volatilitybot.lib.core.sample import MalwareSample
from volatilitybot.machines.machine import Machine

from volatilitybot.conf import config


@pytest.fixture(scope='session')
def golden_image_path(tmpdir_factory):
    gi_path = tmpdir_factory.mktemp('store')
    config.GI_DIR = gi_path
    return gi_path


@pytest.fixture(scope='session')
def store_path(tmpdir_factory):
    store_path = tmpdir_factory.mktemp('store')
    config.STORE_PATH = store_path
    return store_path


@pytest.fixture
def machine_instance():
    machine = Machine('TestMachine', is_64bit=False, is_active=True)
    return machine


@pytest.fixture
def pe_path(store_path):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'putty.exe')

@pytest.fixture
def machine_golden_image(golden_image_path, machine_instance):
    machine_name = machine_instance.machine_name
    test_gi_json = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'pslist.json')).read()

    machine_gi_path = os.path.join(golden_image_path, machine_name)
    os.mkdir(machine_gi_path)
    target_path = os.path.join(machine_gi_path, 'pslist.json')
    with open(target_path, 'w') as f:
        f.write(test_gi_json)
    return target_path


@pytest.fixture
def new_pslist():
    test_gi_data = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'pslist.json')).read()
    test_gi_json = json.loads(test_gi_data)

    malicious_process_info = {
        "Offset(V)": 18446738026626977856,
        "Name": "some_malware.exe",
        "PID": 2488,
        "PPID": 1120,
        "Thds": 2,
        "Hnds": 32,
        "Sess": -1,
        "Wow64": 0,
        "Start": "2018-01-06 10:05:38 UTC+0000",
        "Exit": ""
    }

    legitimate_process_info = {
        "Offset(V)": 18446738026626977856,
        "Name": "taskhost.exe",
        "PID": 12488,
        "PPID": 12,
        "Thds": 2,
        "Hnds": 32,
        "Sess": -1,
        "Wow64": 0,
        "Start": "2018-01-06 10:05:38 UTC+0000",
        "Exit": ""
    }

    test_gi_json.extend([malicious_process_info, legitimate_process_info])
    return test_gi_json


@pytest.fixture
def malware_sample(pe_path):
    sample = MalwareSample(pe_path)
    return sample


@pytest.fixture
def memory_instance():
    memdump = MemoryDump('/tmp/some_non_existing_dump')
    memdump.profile = 'Win7SP0x64'
    return memdump
