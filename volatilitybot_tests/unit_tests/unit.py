import os
import pytest

from volatilitybot.code_extractors.procdump import get_new_processes
from volatilitybot.lib.common import pslist
from volatilitybot.lib.core.memory import MemoryDump
from volatilitybot.machines.machine import Machine
from volatilitybot.lib.common.pe_utils import static_analysis


def test_machine_instance_creation(machine_instance):
    assert isinstance(machine_instance, Machine)
    assert machine_instance.status == 'idle'
    assert machine_instance.active


def test_memory_instance_creation(memory_instance):
    assert isinstance(memory_instance, MemoryDump)
    assert memory_instance.profile == 'Win7SP0x64'


def test_malware_sample(store_path, malware_sample):
    target_path = os.path.join(store_path,
                               '81de431987304676134138705fc1c21188ad7f27edf6b77a6551aa693194485e/81de431987304676134138705fc1c21188ad7f27edf6b77a6551aa693194485e.bin')
    assert malware_sample.id == '81de431987304676134138705fc1c21188ad7f27edf6b77a6551aa693194485e'
    malware_sample.get_sample_data()
    assert malware_sample.sample_data['ephash'] == 'cec32a161e1525357350eee58e4bbe36720e27f52daf635add6b01f81133372d'
    assert malware_sample.sample_data['file_path'] == target_path
    assert malware_sample.sample_data['status'] == 'waiting'


def test_static_analysis(malware_sample):
    result = static_analysis(malware_sample.file_path)
    assert len(result['resources']) == 20
    assert len(result['sections']) == 10
    assert result['imports'][0] == {'name': 'CreateBitmap', 'offset': 4953536}


def test_procdump(machine_golden_image, store_path, machine_instance, memory_instance, malware_sample, new_pslist):
    golden_image = pslist.load_golden_image(machine_instance)
    assert len(golden_image) + 2 == len(new_pslist)

    new_processes = get_new_processes(golden_image, new_pslist)
    assert len(new_processes) == 2
    assert not new_processes[0]['whitelisted']
    assert new_processes[1]['whitelisted']


def test_malfind():
    pass
