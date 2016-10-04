#! /usr/bin/python
import importlib
import logging

from conf.config import CODE_EXTRACTORS
from lib.core.memory import MemoryDump


def analyze_memory(machine_instance, malware_sample):
    """
    Get a machine instance (of an already infected machine), and a malware sample. and analyze the memory
    :param machine_instance:
    :param malware_sample:
    :return:
    """
    result = None

    memory_instance = MemoryDump(machine_instance.get_memory_path())
    if machine_instance.memory_profile is not None:
        profile = machine_instance.memory_profile
        memory_instance.profile = machine_instance.memory_profile
    else:
        memory_instance.identify_profile()
        profile = memory_instance.profile
        if memory_instance.profile is None:
            logging.info('No memory profile was identified for {}'.format(memory_instance.memory_path))
            return None

    logging.info('Identified profile {}'.format(profile))

    memory_path = memory_instance.memory_path

    logging.info('[{}] Memory dump Path is {}'.format(machine_instance.machine_name, memory_path))

    logging.info(
        '[{}] executing code extractors... (Sample ID: {})'.format(machine_instance.machine_name, malware_sample.id))

    for code_extractor_name in CODE_EXTRACTORS:
        try:
            print('[*] Starting code extractor of {}'.format(code_extractor_name))
            extractor = importlib.import_module('code_extractors.{}'.format(code_extractor_name))
            run_extractor = getattr(extractor, 'run_extractor')
            run_extractor(memory_instance, malware_sample, machine_instance=machine_instance)
        except Exception as e:
            logging.error('Execution of code extractor {} has failed: {}'.format(code_extractor_name,e))

    logging.info(
        '[{}] Processing of memory done (Sample ID: {})'.format(machine_instance.machine_name, malware_sample.id))

    result = {'sample_data': malware_sample.sample_data_as_dict()}
    return result
