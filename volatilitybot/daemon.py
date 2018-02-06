import importlib
import logging
import sys

import time
from multiprocessing import Process

import zmq

from volatilitybot.conf.config import MACHINE_INDEX, ACTIVE_MACHINE_TYPE, VIRTUAL_MACHINES_ZMQ
from volatilitybot.lib.core.sample import MalwareSample
from volatilitybot.lib.utils.postgresql import get_sample_queue, update_sample_status

logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def launch_vm_worker(machine_instance):
    logging.info('Started worker for: {}'.format(machine_instance.machine_name))

    worker_name = 'vm_worker_{}'.format(machine_instance.machine_name)
    logging.info('I am worker: {}'.format(worker_name))

    with zmq.Context() as ctx:
        # receive work
        consumer_receiver = ctx.socket(zmq.PULL)
        consumer_receiver.connect(VIRTUAL_MACHINES_ZMQ)
        while True:
            work = consumer_receiver.recv_json()

            file_path = work.get('sample_path')
            sample_sha256 = work.get('sample_sha256')

            logging.info('[{}] Processing {}'.format(worker_name, file_path))

            try:
                logging.info('[{}] processing: {} ...'.format(worker_name, file_path))
                sample_entry = MalwareSample(file_path)
                sample_entry.sha256 = sample_sha256
                sample_entry.get_sample_data()

                result = machine_instance.handle_malware_sample(sample_entry)

                logging.info('Done.')
            except Exception as ex:
                logging.info('[{}] Failed to process sample {}: {}'.format(worker_name, file_path, ex))


def main():
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

        Process(target=launch_vm_worker, args=(machine_dict[machine_instance],)).start()

    with zmq.Context() as ctx:
        with ctx.socket(zmq.PUSH) as zmq_socket:
            zmq_socket.bind(VIRTUAL_MACHINES_ZMQ)
            while True:
                samples_in_queue = get_sample_queue()
                if samples_in_queue:
                    print('got {} samples in queue'.format(len(samples_in_queue)))

                    # push sample to zmq
                    for sample in samples_in_queue:
                        zmq_socket.send_json({
                            'sample_path': sample['sample_path'],
                            'sample_sha256': sample['sha256']
                        })

                        update_sample_status(sample['sha256'], 'sent')

                else:
                    print('Queue is empty, sleeping 5 seconds...')
                    time.sleep(5)


if __name__ == '__main__':
    main()
