import json
import logging
import subprocess

import re

from conf.config import VOLATILITY_PATH


class MemoryDump:
    def __init__(self, dump_path):
        self.profile = None
        self.memory_path = dump_path
        logging.info('Loaded memory dump: {}'.format(self.memory_path))

    def identify_profile(self):
        self.profile = None
        command = VOLATILITY_PATH + ' -f "' + self.memory_path + '" imageinfo'
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

        output_list = proc.stdout.readlines()
        output = ''
        for single_line in output_list:
            current_line = single_line.decode("utf-8").strip()
            result = re.match(r'Suggested Profile\(s\) : (.+)', current_line)

            if result:
                self.profile = result.groups(0)[0].split(',')[0].strip()
                break

        if self.profile:
            logging.info('Got profile {} for {}'.format(self.profile, self.memory_path))

        return
