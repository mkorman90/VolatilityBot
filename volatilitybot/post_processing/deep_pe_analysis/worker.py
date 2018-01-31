import zmq
import random

from multiprocessing import Process

from volatilitybot.conf.config import DAEMON_ZMQ_BACKEND, NUM_DPA_WORKERS
from volatilitybot.post_processing.deep_pe_analysis.analyze import analyze_file


def launch_worker():
    worker_id = random.randrange(1, 10005)
    print('I am worker #{}'.format(worker_id))
    context = zmq.Context()
    # recieve work
    consumer_receiver = context.socket(zmq.PULL)
    consumer_receiver.connect(DAEMON_ZMQ_BACKEND)
    while True:
        work = consumer_receiver.recv_json()

        file_path = work.get('file_path')
        print('Processing {}'.format(file_path))

        try:
            analyze_file(file_path)
            print('Done.')
        except Exception as ex:
            print('Failed to process sample {}: {}'.format(file_path,ex))


def start_workers_pool():
    for i in range(0,NUM_DPA_WORKERS):
        Process(target=launch_worker).start()


if __name__ == '__main__':
    start_workers_pool()
