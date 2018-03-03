#! /usr/bin/python
import logging
import os

from volatilitybot.lib.common import pslist
from volatilitybot.lib.common.utils import calc_sha256, calc_md5, calc_ephash, calc_imphash, calc_sha1
from volatilitybot.lib.core.es_utils import DataBaseConnection
from volatilitybot.lib.core.memory_utils import execute_volatility_command
from volatilitybot.lib.core.sample import SampleDump
from volatilitybot.post_processing.utils.submiter import send_dump_analysis_task


def create_golden_image(machine_instance):
    pass


NAME = 'process_dump'
TIMEOUT = 60

WHITELISTED = ['taskhost.exe', 'wmiapsrv.exe', 'python.exe', 'conhost.exe']


def get_new_processes(golden_image, new_pslist):
    new_processes = []
    for proc in new_pslist:
        new_proc = True
        whitelisted = False
        for proc_gi in golden_image:
            if proc['PID'] == proc_gi['PID']:
                new_proc = False
                break

        if new_proc:
            logging.info('Identified a new process: {} - {}'.format(proc['PID'], proc['Name']))
            if proc['Name'].lower() in WHITELISTED:
                whitelisted = True

            proc.update({'whitelisted': whitelisted})
            new_processes.append(proc)
    return new_processes


def run_extractor(memory_instance, malware_sample, machine_instance=None):
    golden_image = pslist.load_golden_image(machine_instance)
    new_pslist = pslist.get_new_pslist(memory_instance)

    new_processes = get_new_processes(golden_image, new_pslist)

    workdir = os.path.dirname(os.path.realpath(malware_sample.file_path))
    db = DataBaseConnection()

    for procdata in new_processes:
        output = execute_volatility_command(memory_instance, 'procdump',
                                            extra_flags='-p {} -D {}/'.format(procdata['PID'], workdir),
                                            has_json_output=False)

        # Rename the file, to contain process name
        src = workdir + "/executable." + str(procdata['PID']) + ".exe"
        if os.path.isfile(src):

            target_dump_path = workdir + "/" + procdata['Name'] + "." + str(procdata['PID']) + "._exe"
            os.rename(src, target_dump_path)

            current_dump = SampleDump(target_dump_path)
            current_dump.dump_data.update({
                'md5': calc_md5(target_dump_path),
                'sha1': calc_sha1(target_dump_path),
                'sha256': calc_sha256(target_dump_path),
                'imphash': calc_imphash(target_dump_path),
                'ephash': calc_ephash(target_dump_path),
                'process_name': procdata['Name'],
                'source': 'procdump',
                'parent_sample': malware_sample.sample_data['sha256']

            })

            logging.info(
                '[*] Submitting the code to dump analysis engine: {},{},{}'.format(target_dump_path, 'new_process',
                                                                                   malware_sample.id))
            notes = {
                'process_name': procdata['Name'],
                'whitelisted': procdata['whitelisted']
            }
            send_dump_analysis_task(target_dump_path, 'new_process', malware_sample.id, notes=notes)

            current_dump.report()

        else:
            logging.info('Could not dump process {} (PID: {})'.format(procdata['Name'], str(procdata['PID'])))
