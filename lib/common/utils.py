import base64
import hashlib
import json
import logging
import os
import random
import string
import distorm3
import pefile
import re
import requests
import yara
from pefile import PEFormatError

from conf.config import AGENT_KEY, AGENT_PORT, AGENT_CHALLENGE_RESPONSE_KEY, STORE_PATH, YARA_FILE_PATH

READ_OFFSET = 0


def calc_sha256(file_path):
    return hashlib.sha256(open(file_path, 'rb').read()).hexdigest()


def calc_sha1(file_path):
    return hashlib.sha1(open(file_path, 'rb').read()).hexdigest()


def calc_md5(file_path):
    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def get_workdir_path(malware_sample):
    return os.path.dirname(os.path.realpath(malware_sample.file_path))


def agent_generate_challenge():
    challenge = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(64))
    logging.info('Sending challenge for agent authentication: {}'.format(challenge))
    return challenge


def agent_verify_challenge(challenge, response):
    if hashlib.sha256(str(AGENT_CHALLENGE_RESPONSE_KEY + challenge).encode()).hexdigest() == response:
        return True
    return False


def agent_authenticate(machine_instance):
    # Generate random challenge
    challenge = agent_generate_challenge()
    logging.info('Sending challenge for agent ({}) for authentication: {}'.format(machine_instance.machine_name,challenge))

    # Build URL:
    url = 'http://' + machine_instance.ip_address + ':' + AGENT_PORT + '/auth'
    input_json = {'challenge': challenge}
    result = requests.post(url=url, json=input_json)
    if result.status_code == 200:
        if agent_verify_challenge(challenge,result.json()['response']):
            logging.info('Challenge answered successfuly! agent authenticated')
            return True
        else:
            logging.error('Challenge failed for machine {}'.format(machine_instance.machine_name))
    return False


def agent_send_config(machine_instance,custom_config=None):
    # Generate random challenge
    challenge = agent_generate_challenge()
    logging.info('Sending challenge for agent ({}) for authentication: {}'.format(machine_instance.machine_name,challenge))

    # Build URL:
    url = 'http://' + machine_instance.ip_address + ':' + AGENT_PORT + '/conf'
    input_json = {'key': AGENT_KEY, 'vm_name': machine_instance.machine_name, 'ip_address': machine_instance.ip_address, 'challenge': challenge}
    logging.info('Sending configuration to machine {}: {}'.format(machine_instance.machine_name,json.dumps(input_json,indent=4)))

    print('Going to post to {}'.format(url))
    response = requests.post(url=url, json=input_json)

    if response.status_code == 200:
        if agent_verify_challenge(challenge,response.json()['response']):
            if response.json()['rc'] == 0:
                return True
    return False


def agent_send_sample(machine_instance, malware_sample):
    """
    Send malware sample to running machine's agent
    :param ip_address: ip address of the machine
    :param malware_sample: the malware sample instance
    :return:
    """
    # Generate random challenge
    challenge = agent_generate_challenge()
    logging.info('Sending challenge for agent ({}) for authentication: {}'.format(machine_instance.machine_name,challenge))

    if agent_send_config(machine_instance):
        # Build URL:
        url = 'http://' + machine_instance.ip_address + ':' + AGENT_PORT + '/exec'

        with open(malware_sample.file_path, 'rb') as f:
            blob = base64.b64encode(f.read())

        input_json = {'key': AGENT_KEY, 'filename': os.path.basename(malware_sample.file_path).replace(' ', "_"), 'file_blob': blob.decode('utf-8'),
                      'sha256': malware_sample.sha256, 'challenge': challenge}

        print('Going to post to {}'.format(url))
        response = requests.post(url=url, json=input_json)

        if response.status_code == 200:
            if agent_verify_challenge(challenge,response.json()['response']):
                if response.json()['rc'] == 0:
                    return True
    else:
        print('Could not send config, aborting...')
    return False


def pe_read_x_bytes_from_ep(file_path,bytes_to_read=20):

    IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)

    try:
        pe = pefile.PE(file_path)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        logging.info('Got EP: {}'.format(ep))
        # data = pe.get_memory_mapped_image()[ep+READ_OFFSET:ep+READ_OFFSET+int(bytes_to_read)]
        with open(file_path,'rb') as pefile_raw:
            data = pefile_raw.read()[ep+READ_OFFSET:ep+READ_OFFSET+int(bytes_to_read)]

        # Print each decoded instruction
        # This shows how to use the Deocode - Generator
        # Check PE arch. if 0x10b then
        if hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            logging.info('[*] File is 32 bit')
            architechture = distorm3.Decode32Bits
        elif hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            logging.info('[*] File is 64 bit')
            architechture = distorm3.Decode64Bits

        opcode_list = list()
        disasm_data = list()

        iterable = distorm3.DecodeGenerator(ep, data, architechture)
        for (offset, size, instruction, hexdump) in iterable:
            # print("%.8x: %-32s %s" % (offset, hexdump, instruction))
            formatted_line = "%.8x: %-32s %s" % (offset, hexdump.decode('utf-8'), instruction.decode('utf-8'))
            opcode_list.append(formatted_line)

            line = generalize(instruction.decode('utf-8'))
            disasm_data.append(line)

        return hashlib.sha256('|'.join(disasm_data).encode()).hexdigest()

    except PEFormatError as e:
        logging.error('error reading file %s: %s' % (file_path, e))
        return 'failed'

# Assembly generalization - In the future will generalize more instructions i.e: (mov eax,0) = (xor eax eax)
def generalize(line):
    processed_line = re.sub(r"(eax|ebx|ecx|edx|edi|esi)", "reg", line)
    processed_line = re.sub(r"0x[a-f0-9]{1,8}", "hexval", processed_line)

    # Lots of ways to zero a register =]
    processed_line = re.sub(r"xor reg,reg", "zero reg", processed_line)
    processed_line = re.sub(r"mov reg,0", "zero reg", processed_line)
    processed_line = re.sub(r"and reg,0", "zero reg", processed_line)
    processed_line = re.sub(r"mul reg,0", "zero reg", processed_line)
    processed_line = re.sub(r"sub reg,reg", "zero reg", processed_line)
    processed_line = re.sub(r"lea reg,[0]", "zero reg", processed_line)

    # increase one
    processed_line = re.sub(r"inc reg", "+1 reg", processed_line)
    processed_line = re.sub(r"add reg,1", "+1 reg", processed_line)

    # decrease one
    processed_line = re.sub(r"sub reg", "-1 reg", processed_line)
    processed_line = re.sub(r"sub reg,1", "-1 reg", processed_line)

    return processed_line


def calc_ephash(filename, bytes_to_read=64):
    retval = pe_read_x_bytes_from_ep(filename)
    logging.info("[*] Hash of " + str(bytes_to_read) + " Bytes at EP of: " + str(filename) + " : " + retval)
    return retval


def calc_imphash(filename):
    # There is a bug in pefile implenation of imphash in Py3.5. To be fixed
    """
    try:
        pe = pefile.PE(filename)
        return pe.get_imphash()
    except PEFormatError:
        return 'failed'
    """
    return 'failed'


def create_workdir():
    random_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(16))
    target_directory = os.path.join(STORE_PATH,random_string)
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)
        logging.info('Created workdir at {}'.format(target_directory))
        return target_directory
    return None


def yara_scan_file(current_dump, custom_rule_file=None,path=False):
    """
    Perform YARA scan on a file
    :param blob: the text or binary blob
    :param custom_rule_file: optional, choose a different YARA rule file
    :return: a list of matching rules
    """
    if custom_rule_file:
        logging.info('Using custom YARA rule file: {}'.format(custom_rule_file))
        rules = yara.compile(custom_rule_file)
    else:
        rules = yara.compile(YARA_FILE_PATH)

    if path:
        target_path = current_dump
    else:
        target_path = current_dump.binary_path
    with open(target_path, 'rb') as f:
        matching_rules = list()
        yara_result = rules.match(data=f.read())
        if yara_result and len(yara_result) > 0:
            logging.info('YARA scan finished with {} results'.format(len(yara_result)))
            for rule in yara_result:
                rule_matches = list()
                for match in rule.strings:
                    rule_matches.append({'offset': hex(match[0]), 'condition': match[1], 'string': match[2].decode('utf-8', errors='ignore')})
                matching_rules.append({'rule_name': rule.rule, 'matches': rule_matches})
            return matching_rules
    return None


def yara_scan_blob(blob, custom_rule_file=None):
    """
    Perform YARA scan on a binary or text blob
    :param blob: the text or binary blob
    :param custom_rule_file: optional, choose a different YARA rule file
    :return: a list of matching rules
    """
    if custom_rule_file:
        logging.info('Using custom YARA rule file: {}'.format(custom_rule_file))
        rules = yara.compile(custom_rule_file)
    else:
        rules = yara.compile(YARA_FILE_PATH)
    matching_rules = list()
    yara_result = rules.match(data=blob)
    if yara_result and len(yara_result) > 0:
        logging.info('YARA scan finished with {} results'.format(len(yara_result)))
        for rule in yara_result:
            matching_rules.append(rule.rule)
        return matching_rules
    return None