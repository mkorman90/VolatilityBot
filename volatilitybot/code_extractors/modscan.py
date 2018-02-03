import json
import logging
import os

from volatilitybot.lib.core.database import DataBaseConnection
from volatilitybot.lib.core.memory_utils import execute_volatility_command
from volatilitybot.lib.core.sample import SampleDump

from volatilitybot.conf.config import VOLATILITYBOT_HOME
from volatilitybot.lib.common.pe_utils import get_strings
from volatilitybot.lib.common.utils import get_workdir_path, calc_md5, calc_sha256, calc_ephash, calc_imphash, calc_sha1
from volatilitybot.post_processing.deep_pe_analysis.submiter import send_dpa_task
from volatilitybot.post_processing.yara_postprocessor import scan_with_yara


def create_golden_image(memory_instance):
    return execute_volatility_command(memory_instance, 'modscan')


NAME = 'modscan'
TIMEOUT = 120


def run_extractor(memory_instance, malware_sample,machine_instance=None):
    if machine_instance is None:
        return None

    # Whitelist of modules by name, not optimal at all...
    mod_white_list = ['TDTCP.SYS', 'RDPWD.SYS', 'kmixer.sys', 'Bthidbus.sys', 'rdpdr.sys', 'tdtcp.sys', 'tssecsrv.sys']

    # Get golden image data:
    with open(os.path.join(VOLATILITYBOT_HOME, 'GoldenImages', machine_instance.machine_name,
                           'modscan.json')) as data_file:
        modscan_golden_image = json.load(data_file)

    modscan_run = execute_volatility_command(memory_instance, 'modscan')

    db = DataBaseConnection()

    new_modules = []
    for mod in modscan_run:
        new_mod = True
        for mod_gi in modscan_golden_image:
            if mod['File'] == mod_gi['File']:
                if mod['Size'] == mod_gi['Size']:
                    new_mod = False

        for wl_mod in mod_white_list:
            # print '[DEBUG] modscan %s : %s' % (mod['filename'],wl_mod)
            if (mod['Name'] == wl_mod):
                new_mod = False

        if new_mod:
            logging.info('Identified a new module: {} - {}'.format(mod['File'], mod['Size']))
            new_modules.append(mod)

            output = execute_volatility_command(memory_instance, 'moddump',
                                                extra_flags='-b {} -D {}/'.format(mod['Base'],
                                                                                  get_workdir_path(malware_sample)),
                                                has_json_output=False)

            base = mod['Base']
            src = os.path.join(get_workdir_path(malware_sample), "driver." + base[2:] + ".sys")
            dest = os.path.join(get_workdir_path(malware_sample), mod['Name'] + '.' + base[2:] + '.sys')

            try:
                os.rename(src, dest)
            except Exception as e:
                logging.error('Could not rename driver, leaving it as it is... ({})'.format(e) )
                dest = src

            current_dump = SampleDump(dest)

            current_dump.dump_data.update({
                'md5': calc_md5(dest),
                'sha1': calc_sha1(dest),
                'sha256': calc_sha256(dest),
                'imphash': calc_imphash(dest),
                'ephash': calc_ephash(dest),
                'process_name': mod['Name'],
                'source': 'KMD',
                'parent_sample': malware_sample.id

            })
            db.add_dump(current_dump)

            with open(dest + '.strings.json', 'w') as strings_output_file:
                strings_output_file.write(json.dumps(get_strings(current_dump), indent=4))

            try:
                with open(dest + '.yara.json', 'w') as yara_output_file:
                    yara_output_file.write(json.dumps(scan_with_yara(current_dump), indent=4))
            except Exception as ex:
                logging.info('[*] Yara scan failed for {}: {}'.format(dest, ex))

            logging.info('[*] Submitting the code to dpa engine: {},{},{}'.format(dest, 'loaded_driver',
                                                                                  malware_sample.id))
            send_dpa_task(dest, 'loaded_driver', malware_sample.id)

