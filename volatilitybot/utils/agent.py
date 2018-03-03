import hashlib
import os
import base64
import json
import subprocess

from flask import Flask, request
from subprocess import Popen

DETACHED_PROCESS = 0x00000008

app = Flask(__name__)


class AgentInstance:
    DEST_PATH = 'C:\\temp'
    AGENT_KEY = 'ZZ4UNX4MGVSSCQ920O5CFCXR4UOYZ0S1UW70CLF9BC83E1VHA9W9MX0APTQ0WV0G'
    CHALLENGE_RESPONSE_KEY = 'E1P9YK366A6C7OPJOFQDGQAD839Y6LIC1LU6HGCBBUBD90Q4CK4XD2OH0A1PZGNP'
    PORT = 8000

    initial_config = False
    ip_address = ''
    vm_name = 'n/a'
    status = 'idle'

    def generate_response(self, challenge):
        """
        Generate a response for the challenge sent by server in order to authenticate the agent.
        :param challenge: challenge
        :return: response of the challenge
        """
        return hashlib.sha256(str(self.CHALLENGE_RESPONSE_KEY + challenge).encode()).hexdigest()


@app.route('/exec', methods=['POST'])
def handle_file():
    """
    Execute the sample sent by the manager
    :return:
    """
    print('machine {} will handle the sample'.format(agent_instance.vm_name))
    input_json = json.loads(request.get_data().decode('utf-8'))

    response = agent_instance.generate_response(input_json['challenge'])
    print('Got challenge {}, sending response {}'.format(input_json['challenge'], response))

    print(input_json['filename'])
    if input_json['key'] == agent_instance.AGENT_KEY:
        target_file_path = os.path.join(agent_instance.DEST_PATH, input_json['filename'] + '.exe')
        print('Saving file to {}'.format(target_file_path))
        with open(target_file_path, 'wb+') as f:
            f.write(base64.b64decode(input_json['file_blob']))

        # Verify file hash:
        if hashlib.sha256(open(target_file_path, 'rb').read()).hexdigest() == input_json['sha256']:
            # Execute the file
            print('Now executing {}'.format(target_file_path))
            cmd = [target_file_path]
            #p = Popen(cmd, shell=False, stdin=None, stdout=None, stderr=None, close_fds=True,
            #          creationflags=DETACHED_PROCESS)
            pid = Popen(cmd)
            return json.dumps({'response': response, 'rc': 0, 'pid': pid.pid})
    return json.dumps({'response': response, 'rc': 2, 'pid': 0})


@app.route('/conf', methods=['POST'])
def get_config():
    """
    Get configuration from the server
    :return:
    """
    print('Getting configuration update')
    input_json = json.loads(request.get_data().decode('utf-8'))

    response = agent_instance.generate_response(input_json['challenge'])
    print('Got challenge {}, sending response {}'.format(input_json['challenge'], response))

    if input_json['key'] == agent_instance.AGENT_KEY:
        agent_instance.vm_name = input_json['vm_name']
        agent_instance.ip_address = input_json['ip_address']
        agent_instance.initial_config = True
        return json.dumps({'response': response, 'rc': 0})
    return json.dumps({'response': response, 'rc': 2})


@app.route('/auth', methods=['POST'])
def challenge_response():
    """
    Respond to the challenge
    :return:
    """
    print('Initializing challenge response')
    input_json = json.loads(request.get_data().decode('utf-8'))
    response = agent_instance.generate_response(input_json['challenge'])
    print('Got challenge {}, sending response {}'.format(input_json['challenge'], response))
    return json.dumps({'response': response})


if __name__ == '__main__':
    agent_instance = AgentInstance()
    app.run(host='0.0.0.0', port=agent_instance.PORT)
