import os
import sys

import zmq

from volatilitybot.conf.config import POST_PROCESSORS_ZMQ_FRONTEND
from volatilitybot.post_processing.utils.dpa_utils import calc_file_sha256


def send_dump_analysis_task(file_path, dump_type, original_sample_hash, notes=None):
    context = zmq.Context()
    zmq_socket = context.socket(zmq.PUSH)
    zmq_socket.connect(POST_PROCESSORS_ZMQ_FRONTEND)
    # Start your result manager and workers before you start your producers

    if not os.path.isfile(file_path):
        print('ERROR: {} is not a file, or does not exist.'.format(file_path))
        return False

    task = {'file_path': file_path,
            'dump_type': dump_type,
            'original_sample_hash': original_sample_hash,
            'notes': notes}
    zmq_socket.send_json(task)


if __name__ == '__main__':
    sample_sha256 = calc_file_sha256(sys.argv[1])
    send_dump_analysis_task(sys.argv[1], 'original_sample', sample_sha256)

