#! /usr/bin/python
import glob
import logging
import os
import subprocess

from volatilitybot.conf.config import VMRUN_PATH, MACHINE_INDEX
from .machine import Machine


class VMWARE(Machine):
    def initialize(self):
        self.ip_address = MACHINE_INDEX[self.machine_name]['ip_address']
        self.snapshot_name = MACHINE_INDEX[self.machine_name]['snapshot_name']
        self.vmx_path = MACHINE_INDEX[self.machine_name]['vmx_path']
        self.memory_profile = MACHINE_INDEX[self.machine_name]['memory_profile']
        self.is_64bit = MACHINE_INDEX[self.machine_name]['is_64bit']
        self.active = MACHINE_INDEX[self.machine_name]['active']

    def revert(self, wet=True):
        """
        Revert the virtual machine
        :param wet:  used for debbuging, if wet=False - nothing happens
        :return:
        """
        logging.info("[*] [%s] Reverting to snapshot %s:" % (self.machine_name, self.snapshot_name))
        command = VMRUN_PATH + ' revertToSnapshot "' + self.vmx_path + '" ' + self.snapshot_name
        logging.info(command)
        if wet:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            if output:
                logging.error("[!] [%s] Error when starting VM: %s" % (self.machine_name, output))
                return False

            return True
        else:
            logging.info('Dry Run reverting...')
            return True

    def start(self, wet=True):
        """
        Start the virtual machine
        :param wet:  used for debbuging, if wet=False - nothing happens
        :return:
        """
        logging.info("[*] [%s] Starting VM" % self.machine_name)
        command = VMRUN_PATH + ' start "' + self.vmx_path + '"'
        logging.info(command)
        if wet:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            if output:
                logging.error("[!] [%s] Error when starting VM: %s" % (self.machine_name, output))
                return False
            return True
        else:
            logging.info('Dry run start')
            return True

    def suspend(self, wet=True):
        """
        Suspend the virtual machine
        :param wet:  used for debbuging, if wet=False - nothing happens
        :return:
        """
        logging.info("[*] [%s] Suspending VM" % (self.machine_name))
        command = VMRUN_PATH + ' suspend "' + self.vmx_path + '" hard'
        logging.info(command)
        if wet:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            if output:
                logging.error("[!] [%s] Error when suspending: %s" % (self.machine_name, output))
                return False

            return True
        else:
            logging.info('Dry run suspend')
            return True

    def get_memory_path(self, wet=True):
        """
        Get the path to VMEM filr
        :param wet:
        :return:
        """
        logging.info('Searching VMEM in {}'.format(os.path.join(os.path.dirname(os.path.abspath(self.vmx_path)))))
        snapshot_name = max(
            glob.iglob(os.path.join(os.path.dirname(os.path.abspath(self.vmx_path)), '*.vmem')),
            key=os.path.getctime)
        if wet:
            return snapshot_name
        else:
            logging.info('Dry run get_memory_path')
            return None

    def show_info(self):
        print(
            'Machine Name: {}\n\tis_64bit: {}\n\tActive: {}\n\tSnapshot Name: {}\n\tStatus: {}\n\tMemory Profile: {}\n\tVMX Path {}\n\tIP: {}'.format(
                self.machine_name, self.is_64bit, self.active, self.snapshot_name, self.status, self.memory_profile,
                self.vmx_path, self.ip_address))

