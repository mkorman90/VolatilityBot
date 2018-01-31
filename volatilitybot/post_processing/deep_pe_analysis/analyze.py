import distorm3
import pefile
import r2pipe

from tqdm import tqdm

from volatilitybot.post_processing.deep_pe_analysis.utils import calc_file_sha256, calc_func_hash_for_code, add_sample, \
    get_sample, add_function, get_function, add_relation

IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)


def process_file(file_path):
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
        fhash = calc_func_hash_for_code(code, distorm_mode)
        function_hashes.append({'name': func['name'],
                                'f_hash': fhash,
                                })
    print('Created {} function hashes'.format(len(function_hashes)))
    return function_hashes


def analyze_file(file_path):
    sample_sha256 = calc_file_sha256(file_path)
    add_sample(sample_sha256)
    sample_node = get_sample(sample_sha256)

    funcs = process_file(file_path)

    # Skip if no functions found.
    if not funcs:
        return None

    print('Adding functions to neo4j')
    for func in tqdm(funcs):
        props = {'name': func['name']}
        add_function(func['f_hash'], props)

        function_node = get_function(func['f_hash'])
        add_relation(sample_node,function_node)


