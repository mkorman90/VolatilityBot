#! /usr/bin/python
import argparse
import importlib
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from volatilitybot.lib.common.utils import create_workdir
from volatilitybot.lib.core.es_utils import DataBaseConnection
from volatilitybot.lib.core.memory import MemoryDump
from volatilitybot.lib.core.sample import MalwareSample
from volatilitybot.code_extractors.heuristics import run_heuristics
from volatilitybot.conf.config import ACTIVE_MACHINE_TYPE, MACHINE_INDEX, ENABLE_THREADING
from volatilitybot.lib.common.queue import Queue

parser = argparse.ArgumentParser()
parser.add_argument('-f', "--filename", help="The Executable you want to submit")
parser.add_argument('-r', action='store_true', help="Submit a directory, as opposed to -f (file)")
parser.add_argument('-D', action='store_true', help="Execute in daemon mode")
parser.add_argument('--heuristics', action='store_true', help='Execute heuristics in addition to regular analysis')
parser.add_argument('-m', action='store_true', help="Analyze a memory dump, use -f to specify the path")
parser.add_argument('--dump', action='store_true', help="Dump suspicious executable and memory spaces from heuristics")
parser.add_argument('--profile', help="Specify the profile, instead of having volatility detect it automaticly")
args = parser.parse_args()



def main():

    db = DataBaseConnection()
    if not db.es.indices.exists('volatilitybot-samples'):
        db.es.indices.create('volatilitybot-samples')

    if not db.es.indices.exists('volatilitybot-dumps'):
        db.es.indices.create('volatilitybot-dumps')

    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # The m parameter, will tell the analyzer that a memory sample will be processed as opposed to a memory sample
    if args.m:
        logging.info('Will perform memory analysis')
        if args.filename:
            if args.r:
                logging.info('A folder was submitted')
                target_dir = args.filename
                for entry in os.scandir(target_dir):
                    logging.info('Will analyze {}'.format(entry.path))
                    if entry.is_file():
                        target_file = entry.path
                        memdump = MemoryDump(target_file)
                        if args.dump:
                            target_dir = create_workdir()
                        else:
                            target_dir = None

                        if args.profile is not None:
                            memdump.profile = args.profile
                        else:
                            memdump.identify_profile()

                        heuristics_results = run_heuristics(memdump, workdir=target_dir, dump_objects=args.dump)

                        # Save report to file
                        with open(os.path.join(target_dir, 'report.json'), 'w') as report:
                            report.write(json.dumps(heuristics_results, indent=4))
            else:
                logging.info('A single memory dump was submitted for processing')
                target_file = args.filename
                memdump = MemoryDump(target_file)

                if args.profile is not None:
                    memdump.profile = args.profile
                else:
                    memdump.identify_profile()

                target_dir = create_workdir()

                heuristics_results = run_heuristics(memdump, workdir=target_dir, dump_objects=args.dump)

                # Save report to file
                with open(os.path.join(target_dir, 'report.json'), 'w') as report:
                    report.write(json.dumps(heuristics_results, indent=4))

    # Load malware sample specified in param, submit it to Queue
    elif args.filename:
        if args.r:
            logging.info('A folder was submitted')
            target_dir = args.filename
            for entry in os.scandir(target_dir):
                logging.info('Submitting {}'.format(entry.path))
                if entry.is_file():
                    malware_sample = MalwareSample(entry.path)
                    malware_sample.get_sample_data()
                    if malware_sample.enqueue():
                        logging.info('Sample {} enqueued...'.format(malware_sample.sample_data['sha256']))
                    else:
                        logging.info('Sample already exists in DB')
        else:
            logging.info('A sample was submitted for processing')
            target_file = args.filename
            malware_sample = MalwareSample(target_file)
            malware_sample.get_sample_data()
            if malware_sample.enqueue():
                logging.info('Sample {} enqueued...'.format(malware_sample.sample_data['sha256']))
            else:
                logging.info('Sample already exists in DB')

    # Execute VolatilityBot in daemon mode, analyze everything in queue
    elif args.D:
        logging.info('===========================Starting VolatilityBot in Daemon mode===========================')

        # Get list of samples waiting in queue
        waiting_samples = []  # db_connection.get_waiting_sample_queue()
        logging.info('Waiting samples in queue: {}'.format(waiting_samples))

        # Initialize queue (no pools for now, it is more simple to run two volatilitybot instances)
        sample_queue = Queue()
        sample_queue.get_waiting_sample_queue()

        # Initialize the machines
        machine = importlib.import_module('volatilitybot.machines.{}'.format(ACTIVE_MACHINE_TYPE.lower()))
        machine_class = getattr(machine, ACTIVE_MACHINE_TYPE)

        machine_dict = {}
        for machine_instance in MACHINE_INDEX:
            machine_dict[machine_instance] = machine_class(machine_instance)
            machine_dict[machine_instance].initialize()
            machine_dict[machine_instance].show_info()

            # Remove machine from index if it is not active
            if not machine_dict[machine_instance].active:
                removed_machine = machine_dict.pop(machine_dict[machine_instance].machine_name)
                logging.info('Machine {} was removed from index, because it is inactive in configuration'.format(
                    removed_machine.machine_name))
                removed_machine = None

        # Launch an executor for each VM, and start making the threads pulling samples from DB
        while True:
            with ThreadPoolExecutor(max_workers=len(MACHINE_INDEX)) as executor:
                while not sample_queue.isEmpty():
                    logging.info('Samples in queue: {}'.format(sample_queue.size()))
                    next_sample = sample_queue.dequeue()
                    next_sample.print_sample_details()
                    vm_for_execution_found = False
                    while not vm_for_execution_found:
                        for machine_instance in machine_dict:
                            if (machine_dict[machine_instance].status == 'idle') and (not vm_for_execution_found):
                                logging.info(
                                    'The VM {} will handle the sample ID: {}'.format(
                                        machine_dict[machine_instance].machine_name, next_sample.sample_data['sha256']))
                                vm_for_execution_found = True

                                # Execution code happens here, hopefully in a thread
                                # which will update the status of the machine instance to waiting when done..
                                if ENABLE_THREADING:
                                    future = executor.submit(machine_dict[machine_instance].handle_malware_sample,
                                                             next_sample)
                                else:
                                    machine_dict[machine_instance].handle_malware_sample(next_sample)
                        if not vm_for_execution_found:
                            logging.info(
                                'All machines are busy... Will retry in 5 seconds ({} Samples in queue)'.format(
                                    sample_queue.size() + 1))
                            time.sleep(5)

            logging.info('No more samples in queue...')
            logging.info('Sleeping 5 seconds before checking again...')
            time.sleep(5)
            sample_queue.get_waiting_sample_queue()
