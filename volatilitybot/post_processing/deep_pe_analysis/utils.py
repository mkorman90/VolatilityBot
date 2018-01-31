import distorm3
import hashlib
import re
import py2neo

from py2neo import Node, Relationship

# set up authentication parameters
from volatilitybot.conf.config import NEO4j_USER, NEO4j_PASS

py2neo.authenticate("localhost:7474", NEO4j_USER, NEO4j_PASS)

# connect to authenticated graph database
graph = py2neo.Graph("http://localhost:7474/db/data/")


def get_function(func_hash):
    selected = graph.node_selector.select('function', **{'fhash': func_hash})
    if selected.first():
        return selected.first()
    return None


def get_sample(f_sample_hash):
    selected = graph.node_selector.select('sample', **{'sample_hash': f_sample_hash})
    if selected.first():
        return selected.first()
    return None


def add_function(func_hash, props):
    props.update({'fhash': func_hash})

    if get_function(func_hash):
        return False

    # TODO: This should also add the function to elastic, including the disassmebly so it could be searched for!

    tx = graph.begin()
    func = Node('function', **props)
    tx.create(func)
    tx.commit()
    return True


def add_sample(f_sample_hash, note=''):
    props = {'sample_hash': f_sample_hash}

    if get_sample(f_sample_hash):
        return False
    tx = graph.begin()
    func = Node('sample', **props)
    tx.create(func)
    tx.commit()
    return True


def add_relation(sample_node, function_node):
    tx = graph.begin()
    tx.create(Relationship(sample_node, 'calls', function_node))
    tx.commit()


def calc_file_sha256(f_path):
    return hashlib.sha256(open(f_path, 'rb').read()).hexdigest()


def calc_func_hash_for_code(code, distorm_mode):
    hasher = hashlib.sha256()
    for offset, size, instruction, hexdump in distorm3.DecodeGenerator(0, bytes(code), distorm_mode):
        # print(offset, size, instruction, hexdump)
        inst_string = instruction.decode()
        inst_string = re.sub(r'\[0x[a-f0-9]{6,}\]', 'hexaddr', inst_string)
        inst_string = re.sub(r'PUSH DWORD 0x[a-f0-9]{6,}', 'PUSH DWORD hexaddr', inst_string)
        hasher.update(inst_string.encode())
    func_hash = hasher.hexdigest()
    return func_hash
