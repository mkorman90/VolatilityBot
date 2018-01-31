import os
import time
import sys
import zmq

from volatilitybot.conf.config import DAEMON_ZMQ_FRONTEND


def send_task(file_path):
    context = zmq.Context()
    zmq_socket = context.socket(zmq.PUSH)
    zmq_socket.connect(DAEMON_ZMQ_FRONTEND)
    # Start your result manager and workers before you start your producers

    if not os.path.isfile(file_path):
        print('ERROR: {} is not a file, or does not exist.'.format(file_path))
        return False

    task = {'file_path': file_path}
    zmq_socket.send_json(task)


if __name__ == '__main__':
    send_task(sys.argv[1])

