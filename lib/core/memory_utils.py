import json
import logging
import os
import subprocess

import re

from conf.config import VOLATILITY_PATH
from lib.common.pe_utils import static_analysis, get_strings
from lib.core.memory import MemoryDump
from lib.core.sample import SampleDump
from machines.machine import Machine


def dump_process(memory_instance, pid, target_dump_dir, process_name=None, memdump=False):
    if memdump:
        dump_method = 'memdump'
    else:
        dump_method = 'procdump'

    output = execute_volatility_command(memory_instance, dump_method,
                                        extra_flags='-p {} -D {}/'.format(pid, target_dump_dir), has_json_output=False)

    if memdump:
        src = os.path.join(target_dump_dir, str(pid) + ".dmp")
    else:
        src = os.path.join(target_dump_dir, "executable." + str(pid) + ".exe")

    if os.path.isfile(src):
        extension = '.dmp' if memdump else '._exe'
        target_dump_path = os.path.join(target_dump_dir, process_name + "." + str(pid) + extension)
        os.rename(src, target_dump_path)

        dump_obj = SampleDump(target_dump_path)
        dump_obj.calculate_hashes()

        with open(target_dump_path + '.strings.json', 'w') as strings_output_file:
            strings_output_file.write(json.dumps(get_strings(dump_obj), indent=4))

        with open(target_dump_path + '.static_analysis.json', 'w') as strings_output_file:
            strings_output_file.write(json.dumps(static_analysis(dump_obj), indent=4))



        logging.info('Dumping of process with pid {} succeeded'.format(pid))
        return True

    logging.error('Dumping of process with pid {} failed: {}'.format(pid, output))
    return False


def dump_dll(memory_instance, target_pid, image_base, target_dump_dir):
    output = execute_volatility_command(memory_instance, 'dlldump',
                                        extra_flags='-p {} -b {} -D {}/'.format(target_pid, image_base,
                                                                                target_dump_dir))
    logging.debug('Dumping DLL {}'.format(output))

    # IndexError if output 0 does not exists, because there was a problem with the dump
    try:
        if output[0]['Result'].startswith('OK'):
            status, module_dump_path = output[0]['Result'].split(':')
            src = os.path.join(target_dump_dir, module_dump_path.strip())
            if os.path.isfile(src):
                dst = os.path.join(target_dump_dir,
                                   'module.' + str(target_pid) + '.' + str(hex(output[0]['Module Base'])) + '.' + output[0][
                                       'Module Name'].replace('.', '_') + '.dll')
                os.rename(src, dst)
                logging.info('Saved as {}'.format(dst))

                dump_obj = SampleDump(dst)
                dump_obj.calculate_hashes()

                # Post processors on output...
                with open(dst + '.strings.json', 'w') as strings_output_file:
                    strings_output_file.write(json.dumps(get_strings(dump_obj),indent=4))

                with open(dst + '.static_analysis.json', 'w') as strings_output_file:
                    strings_output_file.write(json.dumps(static_analysis(dump_obj), indent=4))
    except IndexError:
        logging.warning('Problem dumping pid: {} at base: {}: {}'.format(target_pid,image_base,output))

def execute_volatility_command(memory_instance, plugin_name, extra_flags=None, has_json_output=True):
    """
    Execute a volatility command, and return the output, if it is json, return as dict
    :param memory_instance: memory dump object
    :param plugin_name: name of the plugin to execute, i.e malfind
    :param extra_flags: Additional flags the plugin might use, i.e dumpdir -D
    :param has_json_output: if the plugin has json output, add the flag. enabled by default
    :return:
    """
    profile = memory_instance.profile
    memory_path = memory_instance.memory_path

    command = '{} --profile {} -f "{}" {} '.format(VOLATILITY_PATH, profile, memory_path, plugin_name)

    # If the command has additional flags, add them here
    if extra_flags is not None:
        command += extra_flags + ' '

    # If the command has json output, add the output flag
    if has_json_output:
        command += '--output=json'

    print(command)

    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output_list = proc.stdout.readlines()
    output = ''
    for single_line in output_list:
        output += single_line.decode("utf-8")

    final_output = []
    if has_json_output:
        try:
            # Clean the output, to only contain the JSON
            match = re.search(r'(\{.+\})', output)
            if match:
                output = match.group(1)
                plugin_output = json.loads(output)
                # Sort the plugin data to dictionary with key:value.
                for row in plugin_output['rows']:
                    entry = dict()
                    for column_index, parameter in enumerate(row):
                        entry[plugin_output['columns'][column_index]] = parameter
                    final_output.append(entry)
                return final_output
            else:
                logging.error('The output of this plugin was not json... returning as raw')
                return final_output
        except (KeyError, ValueError):
            # If there is a problem with loading the JSON, return for this plugin.
            logging.exception('Corrupted JSON file')
            return None
    else:
        return output
