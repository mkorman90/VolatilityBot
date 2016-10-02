#! /usr/bin/python
import importlib
import json
import logging
import os
import shutil
import time

# Initialize the machines
from conf.config import ACTIVE_MACHINE_TYPE, MACHINE_INDEX, VOLATILITYBOT_HOME, CODE_EXTRACTORS
from lib.common.pslist import get_new_pslist
from lib.core.memory import MemoryDump

machine = importlib.import_module('machines.{}'.format(ACTIVE_MACHINE_TYPE.lower()))
machine_class = getattr(machine, ACTIVE_MACHINE_TYPE)

machine_dict = {}
for machine_instance in MACHINE_INDEX:
    machine_dict[machine_instance] = machine_class(machine_instance)
    machine_dict[machine_instance].initialize()
    machine_dict[machine_instance].show_info()

for vm in MACHINE_INDEX:
    logging.info("[*] VM name: %s Enabled: %s" % (machine_dict[vm].machine_name, machine_dict[vm].active))
    if machine_dict[vm].active:
        print('  [*] [{}] Creating Golden image for this machine!'.format(machine_dict[vm].machine_name))

        print("[*] Reverting Machine...")
        machine_dict[vm].revert()
        machine_dict[vm].start()
        print("[*] Sleeping 5 seconds...")
        time.sleep(5)
        print("[*] Suspending Machine...")
        machine_dict[vm].suspend()
        print("[*] Acquiring memory...")
        memdump = MemoryDump(machine_dict[vm].get_memory_path())

        gi_dir = os.path.join(VOLATILITYBOT_HOME, 'GoldenImage', machine_dict[vm].machine_name)

        if os.path.exists(gi_dir):
            print("[*] Folder already exists, deleting and recreating")
            shutil.rmtree(gi_dir)
            os.mkdir(gi_dir)
        else:
            print("[*] Folder does not exist, recreating")
            os.mkdir(gi_dir)

        print("[*] Executing Golden Image modules")


        for code_extractor_name in CODE_EXTRACTORS:
            print('[*] Starting code extractor of {}'.format(code_extractor_name))
            extractor = importlib.import_module('code_extractors.{}'.format(code_extractor_name))
            create_golden_image_func = getattr(extractor, 'create_golden_image')

            with open(os.path.join(gi_dir, code_extractor_name + '.json'),'w+') as golden_image_file:
                golden_image_file.write(json.dumps(create_golden_image_func(memdump), indent=4))

        '''
        with open(os.path.join(gi_dir, 'modscan.json'), 'w+') as golden_image_file:
            golden_image_file.write(json.dumps(modscan.create_golden_image(machine_dict[vm]), indent=4))
        '''

        # Getting pslist golden image data
        with open(os.path.join(gi_dir, 'pslist.json'), 'w+') as golden_image_file:
            golden_image_file.write(json.dumps(get_new_pslist(memdump), indent=4))

        print("[*] Done for Machine: {}".format(machine_dict[vm].machine_name))

print("[*] Done. Enjoy! ")
