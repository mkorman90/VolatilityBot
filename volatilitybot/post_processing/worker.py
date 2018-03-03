import random
from multiprocessing import Process

import zmq

from volatilitybot.conf.config import POST_PROCESSORS_ZMQ_BACKEND, NUM_DPA_WORKERS
from volatilitybot.post_processing.analyze import process_file


def launch_worker():
    worker_id = random.randrange(1, 10005)
    print('I am worker #{}'.format(worker_id))
    context = zmq.Context()
    # receive work
    consumer_receiver = context.socket(zmq.PULL)
    consumer_receiver.connect(POST_PROCESSORS_ZMQ_BACKEND)
    while True:
        work = consumer_receiver.recv_json()

        file_path = work.get('file_path')
        original_sample_hash = work.get('original_sample_hash')
        dump_type = work.get('dump_type')
        dump_notes = work.get('notes')
        print('Processing {}'.format(file_path))

        process_name = dump_notes.get('process_name')
        whitelisted = dump_notes.get('whitelisted')

        try:
            process_file(file_path, dump_type, original_sample_hash, dump_notes=process_name, whitelisted=whitelisted)
            print('Done.')
        except Exception as ex:
            print('Failed to process sample {}: {}'.format(file_path, ex))


def start_workers_pool():
    if NUM_DPA_WORKERS == 0:
        launch_worker()
    else:
        for i in range(0, NUM_DPA_WORKERS):
            Process(target=launch_worker).start()


if __name__ == '__main__':
    start_workers_pool()
