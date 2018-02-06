#! /usr/bin/python
import json
import logging
import os
import time

from volatilitybot.conf.config import DEFAULT_SLEEP_TIME
from volatilitybot.lib.common.utils import agent_send_sample
from volatilitybot.lib.common.analyze_memory import analyze_memory
from volatilitybot.lib.utils.postgresql import update_sample_status


class Machine:
    def __init__(self, machine_name, is_64bit=False, is_active=True):
        self.is_64bit = is_64bit
        self.active = is_active
        self.machine_name = machine_name
        self.snapshot_name = None
        self.memory_profile = None
        self.status = 'idle'
        self.vm_status = None
        self.ip_address = None

    def initialize(self):
        """
        Abstract implementation
        :return:
        """
        raise NotImplementedError

    def revert(self):
        self.vm_status = 'reverted'
        """
        Abstract implementation
        :return: boolean status
        """
        raise NotImplementedError

    def start(self):
        self.vm_status = 'running'
        """
        Abstract implementation
        :return: boolean status
        """
        raise NotImplementedError

    def suspend(self):
        self.vm_status = 'suspended'
        """
        Abstract implementation
        :return: boolean status
        """
        raise NotImplementedError

    def send_malware_sample(self, malware_sample):
        """
        Submit the malware sample to the machine, in order to execute it
        :param malware_sample:
        :return:
        """
        logging.info(
            'Going to send malware sample {} to machine {} with ip {}'.format(malware_sample.sample_data['sha256'], self.machine_name,
                                                                              self.ip_address))
        if agent_send_sample(self, malware_sample):
            return True
        return False

    def handle_malware_sample(self, malware_sample):
        """
        Handle all the VM operations (revert,send sample, suspend and at last analyze)
        :param malware_sample:
        :return:
        """
        logging.info(
            'Machine {}  Will handle sample ID {}'.format(self.machine_name, malware_sample.sample_data['sha256']))

        result = None

        logging.info('[{}] Reverting (Sample ID: {})'.format(self.machine_name, malware_sample.sample_data['sha256']))
        if self.revert() and self.start():

            # Wait 4 seconds for network to reconnect in VM
            logging.info('[{}] Waiting 4 seconds for network to restore...'.format(self.machine_name))
            time.sleep(4)

            logging.info(
                '[{}] Executing (Sample ID: {})'.format(self.machine_name, malware_sample.sample_data['sha256']))
            if self.send_malware_sample(malware_sample):

                logging.info('Sleeping {} seconds...'.format(DEFAULT_SLEEP_TIME))
                time.sleep(DEFAULT_SLEEP_TIME)

                logging.info(
                    '[{}] Suspending and processing... (Sample ID: {})'.format(self.machine_name,
                                                                               malware_sample.sample_data['sha256']))

                if self.suspend():
                    result = analyze_memory(self, malware_sample)
                else:
                    logging.error('Could not suspend the machine {}, analysis will fail...'.format(self.machine_name))

            else:
                logging.error('Could not send sample to machine {}'.format(self.machine_name))

            logging.info(
                'Machine {} finished processing sample ID {} result: {}'.format(self.machine_name,
                                                                                malware_sample.sample_data['sha256'],
                                                                                result))
        status = 'failed'

        if result is not None:
            with open(os.path.join(os.path.dirname(os.path.realpath(malware_sample.file_path)),
                                   'report' + str(malware_sample.sample_data['sha256']) + '.json'), 'w+') as result_file:
                result_file.write(json.dumps(result, indent=4))

            # Change the status of sample to completed, and machine back to idle
            status = 'completed'

        if status == 'failed':
            self.cleanup()

        update_sample_status(malware_sample.sample_data['sha256'],status)
        logging.info(
            'Processing of sample {} by {} completed with status: {}.'.format(malware_sample.sample_data['sha256'],
                                                                              self.machine_name,
                                                                              status))
        self.status = 'idle'

    def get_memory_path(self):
        raise NotImplementedError

    def cleanup(self):
        pass

    def show_info(self):
        print(
            'Machine Name: {}\n\tis_64bit: {}\n\tActive: {}\n\tSnapshot Name: {}\n\tStatus: {}\n\tMemory Profile: {}\n\tIP: {}'.format(
                self.machine_name, self.is_64bit, self.active, self.snapshot_name, self.status, self.memory_profile,
                self.ip_address))
