import distorm3
import pefile
import r2pipe

from tqdm import tqdm

from volatilitybot.post_processing.deep_pe_analysis.utils import calc_file_sha256, calc_func_hash_for_code, \
    add_sample_to_graphdb, \
    get_sample, add_function_to_graphdb, get_function, add_call_relation_to_graphdb, add_dump_to_graphdb, \
    add_dump_relation_to_graphdb, get_dump, add_function_to_es

IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)


def get_file_functions(file_path):
    r2 = r2pipe.open(file_path)
    r2.cmd('aa;aac')
    funcs = r2.cmdj('aflj')

    pe = pefile.PE(file_path)
    distorm_mode = distorm3.Decode32Bits if hex(
        pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC else distorm3.Decode64Bits

    if not funcs:
        return None

    function_hashes = []
    print('hashing functions')
    for func in tqdm(funcs):
        start = func['offset'] - pe.OPTIONAL_HEADER.ImageBase
        end = start + func['size']
        code = pe.write()[start:end]

        if len(set(code)) == 1:
            print('Repeating pattern found. skipping this function')
            continue

        disasm,function_hash = calc_func_hash_for_code(code, distorm_mode)
        function_hashes.append({'name': func['name'],
                                'f_hash': function_hash,
                                'disasm': disasm
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

        # Skip function if it cotains only zeros:


        add_function_to_graphdb(func['f_hash'], props)

        # Add function to elastic search:
        add_function_to_es(func)

        function_node = get_function(func['f_hash'])
        add_call_relation_to_graphdb(dump_node, function_node)


