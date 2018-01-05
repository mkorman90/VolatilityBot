#! /usr/bin/python
import json
import logging
import os

from volatilitybot.lib.common import pslist
from volatilitybot.lib.core.database import DataBaseConnection
from volatilitybot.lib.core.memory_utils import execute_volatility_command
from volatilitybot.lib.core.sample import SampleDump
from volatilitybot.lib.common.utils import calc_sha256, calc_md5, calc_ephash, calc_imphash, calc_sha1
from volatilitybot.lib.common.pe_utils import static_analysis, get_strings
from volatilitybot.post_processing.yara_postprocessor import scan_with_yara


def create_golden_image(machine_instance):
    pass


NAME = 'process_dump'
TIMEOUT = 60


def run_extractor(memory_instance, malware_sample, machine_instance=None):
    golden_image = pslist.load_golden_image(machine_instance)
    new_pslist = pslist.get_new_pslist(memory_instance)

    new_processes = []
    for proc in new_pslist:
        new_proc = True
        for proc_gi in golden_image:
            if proc['PID'] == proc_gi['PID']:
                new_proc = False
                break

            # TODO! Local patch!! Remove on production!!
            if proc['Name'] == 'wmiprvse.exe':
                new_proc = False
                break

        if new_proc:
            logging.info('Identified a new process: {} - {}'.format(proc['PID'], proc['Name']))
            new_processes.append(proc)

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
            db.add_dump(current_dump)

            # Load post processing modules here, if needed
            with open(target_dump_path + '.strings.json', 'w') as strings_output_file:
                strings_output_file.write(json.dumps(get_strings(current_dump), indent=4))

            with open(target_dump_path + '.static_analysis.json', 'w') as strings_output_file:
                strings_output_file.write(json.dumps(static_analysis(current_dump), indent=4))

            with open(target_dump_path + '.yara.json', 'w') as yara_output_file:
                yara_output_file.write(json.dumps(scan_with_yara(current_dump), indent=4))
        else:
            logging.info('Could not dump process {} (PID: {})'.format(procdata['Name'], str(procdata['PID'])))
