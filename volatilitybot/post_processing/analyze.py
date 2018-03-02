import json

import distorm3
import pefile
import r2pipe
from tqdm import tqdm

from volatilitybot.post_processing.utils.dpa_utils import calc_file_sha256, analyze_function, \
    add_sample_to_graphdb, \
    get_sample, add_function_to_graphdb, get_function, add_call_relation_to_graphdb, add_dump_to_graphdb, \
    add_dump_relation_to_graphdb, get_dump, add_function_to_es, add_api_call_to_graphdb, get_api_call, \
    add_api_call_relation_to_graphdb

IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)


def get_file_functions(file_path):
    r2 = r2pipe.open(file_path)
    r2.cmd('aaaa;aac')
    funcs = r2.cmdj('aflj')

    pe = pefile.PE(file_path)
    distorm_mode = distorm3.Decode32Bits if hex(
        pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC else distorm3.Decode64Bits

    if not funcs:
        return None

    # Create a index of symbols
    symbols = r2.cmd('isj')
    symbols_j = json.loads(symbols)
    symbols = {}
    for symbol in symbols_j:
        vaddr = symbol['vaddr']
        name = symbol['name']
        symbols[vaddr] = name

    print('{} symbols found!'.format(len(symbols)))

    function_hashes = []
    print('hashing functions')
    for func in tqdm(funcs):
        start = func['offset'] - pe.OPTIONAL_HEADER.ImageBase
        end = start + func['size']
        code = pe.write()[start:end]

        if len(set(code)) == 1:
            print('Repeating pattern found. skipping this function')
            continue

        disasm, api_calls, function_hash = analyze_function(code, distorm_mode, symbols)
        function_hashes.append({'name': func['name'],
                                'f_hash': function_hash,
                                'disasm': disasm,
                                'api_calls': api_calls
                                })
    print('Created {} function hashes'.format(len(function_hashes)))
    return function_hashes


def process_file(file_path, dump_type, original_sample_hash, dump_notes=None):
    add_sample_to_graphdb(original_sample_hash)
    sample_node = get_sample(original_sample_hash)

    dump_hash = calc_file_sha256(file_path)
    add_dump_to_graphdb(dump_hash, dump_type, dump_notes)
    dump_node = get_dump(dump_hash)

    add_dump_relation_to_graphdb(sample_node, dump_node)

    # Get file functions for neo4j
    funcs = get_file_functions(file_path)

    # Skip if no functions found.
    if not funcs:
        return None

    print('Adding functions to neo4j')

    for func in tqdm(funcs):
        props = {'name': func['name']}

        # Skipping too small function
        if len(func['disasm']) <= 3:
            continue

        add_function_to_graphdb(func['f_hash'], props)

        # Add function to elastic search:
        add_function_to_es(func)

        function_node = get_function(func['f_hash'])
        add_call_relation_to_graphdb(dump_node, function_node)

        api_calls = func.get('api_calls')
        if api_calls:
            for api_call_name in api_calls:
                call = get_api_call(api_call_name)
                if not call:
                    add_api_call_to_graphdb(api_call_name)
                    call_node = get_api_call(api_call_name)
                    add_api_call_relation_to_graphdb(function_node, call_node)

    # TODO:

    # Perform static analysis on the dump

    # Scan with YARA

    # Extract strings

    # Scan with Clam?

    print('Processing of dump at {} done...'.format(file_path))
