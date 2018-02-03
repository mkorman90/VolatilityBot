import distorm3
import hashlib
import re
import py2neo
from elasticsearch import Elasticsearch
import pendulum

from py2neo import Node, Relationship
from py2neo.database.status import ConstraintError
# set up authentication parameters
from volatilitybot.conf.config import NEO4j_USER, NEO4j_PASS, ES_HOSTS

py2neo.authenticate("localhost:7474", NEO4j_USER, NEO4j_PASS)

# connect to authenticated graph database
graph = py2neo.Graph("http://localhost:7474/db/data/")

DPA_FUNCTIONS_INDEX = 'volatilitybot-functions'


def _initialize_dpa():
    """
    Initialize neo4j DB, with relevant indices, etc...
    :return:
    """
    try:
        graph.schema.create_index('sample', 'sample_hash')
    except Exception as ex:
        print(ex)
        if ex.__class__.__name__ != 'ConstraintViolationException':
            exit(100)
        print('sample index already exists...')

    try:
        graph.schema.create_index('function', 'fhash')
    except Exception as ex:
        print(ex)
        if ex.__class__.__name__ != 'ConstraintViolationException':
            exit(100)

    try:
        graph.schema.create_index('dump', 'dump_hash')
    except Exception as ex:
        print(ex)
        if ex.__class__.__name__ != 'ConstraintViolationException':
            exit(100)

    es = Elasticsearch(ES_HOSTS)
    if not es.indices.exists(DPA_FUNCTIONS_INDEX):
        es.indices.create(DPA_FUNCTIONS_INDEX)


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


def get_dump(f_dump_hash):
    selected = graph.node_selector.select('dump', **{'dump_hash': f_dump_hash})
    if selected.first():
        return selected.first()
    return None


def add_function_to_graphdb(func_hash, props):
    props.update({'fhash': func_hash})

    if get_function(func_hash):
        return False

    # TODO: This should also add the function to elastic, including the disassmebly so it could be searched for!

    tx = graph.begin()
    func = Node('function', **props)
    tx.create(func)
    tx.commit()
    return True


def add_function_to_es(function_info):
    es = Elasticsearch(ES_HOSTS)
    function_name = function_info['name']
    function_hash = function_info['f_hash']
    function_disasm = function_info['disasm']
    first_seen = pendulum.now().isoformat()
    es.index(index=DPA_FUNCTIONS_INDEX, doc_type='function', id=function_hash, body={'name': function_name,
                                                                                     'disasm': function_disasm,
                                                                                     'first_seen': first_seen
                                                                                     })


def add_sample_to_graphdb(f_sample_hash, note=''):
    props = {'sample_hash': f_sample_hash}

    if get_sample(f_sample_hash):
        return False
    tx = graph.begin()
    func = Node('sample', **props)
    tx.create(func)
    tx.commit()
    return True


def add_dump_to_graphdb(f_dump_hash, dump_type, dumps_notes):
    props = {'dump_hash': f_dump_hash,
             'dump_type': dump_type,
             'notes': dumps_notes}

    if get_dump(f_dump_hash):
        return False
    tx = graph.begin()
    func = Node('dump', **props)
    tx.create(func)
    tx.commit()
    return True


def add_call_relation_to_graphdb(sample_node, function_node):
    tx = graph.begin()
    tx.create(Relationship(sample_node, 'calls', function_node))
    tx.commit()


def add_dump_relation_to_graphdb(sample_node, dump_node):
    tx = graph.begin()
    tx.create(Relationship(sample_node, 'executed', dump_node))
    tx.commit()


def calc_file_sha256(f_path):
    return hashlib.sha256(open(f_path, 'rb').read()).hexdigest()


def calc_func_hash_for_code(code, distorm_mode):
    hasher = hashlib.sha256()
    disassmebly = []
    for offset, size, instruction, hexdump in distorm3.DecodeGenerator(0, bytes(code), distorm_mode):
        disassmebly.append({
            'offset': offset,
            'size': size,
            'hexdump': hexdump,
            'instruction': instruction
        })
        # print(offset, size, instruction, hexdump)
        inst_string = instruction.decode()
        inst_string = re.sub(r'\[0x[a-f0-9]{6,}\]', 'hexaddr', inst_string)
        inst_string = re.sub(r'PUSH DWORD 0x[a-f0-9]{6,}', 'PUSH DWORD hexaddr', inst_string)
        hasher.update(inst_string.encode())
    func_hash = hasher.hexdigest()
    return disassmebly, func_hash
