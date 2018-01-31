from multiprocessing import Pool
import random

from volatilitybot.conf.config import NUM_DPA_WORKERS
from volatilitybot.post_processing.deep_pe_analysis.daemon import launch_daemon
from volatilitybot.post_processing.deep_pe_analysis.worker import launch_worker


def get_daemon():
    return multiprocessing.Process(
        name='daemon',
        target=launch_daemon,
    )


def get_worker():
    return multiprocessing.Process(
        name='worker {}'.format(random.randrange(1, 10005)),
        target=launch_worker,
    )


if __name__ == '__main__':
    d = get_daemon()
    d.daemon = True
    workers = [get_worker() for i in range(0,NUM_DPA_WORKERS)]

    d.start()

    for worker in workers:
        worker.start()
        worker.join()

    d.join()

