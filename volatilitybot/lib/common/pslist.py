#! /usr/bin/python

import json
import os

from volatilitybot.conf.config import GI_DIR
from volatilitybot.lib.core.memory_utils import execute_volatility_command


def load_golden_image(machine_instance):
    with open(os.path.join(GI_DIR,machine_instance.machine_name,'pslist.json')) as data_file:
        return json.load(data_file)


def get_new_pslist(memory_instance):
    """
    Get output of Volatility pslist command
    :param memory_instance: Reference to memory instance
    :return: list of currently running processes
    """
    return execute_volatility_command(memory_instance, 'pslist')


