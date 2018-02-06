import binascii
import json
import logging
import os
import re
import string
import struct

import distorm3
import pefile
import yara

from volatilitybot.conf.config import SEMANTIC_YARA_RULES_PATH

NAME = None
TIMEOUT = 60

printable = set(string.printable)

api_dictionary = {}
string_dictionary = {}

api_dictionary_by_name = {}
string_dictionary_by_name = {}

yara_matches_list = []

any_rules_matched = False

regex_pattern = re.compile("^([A-F0-9]{2})$")
regex_pattern_wildcard = re.compile("^(\[(\d{1,3}|\-)\])$")


# Callback for YARA signatures - Processes the recieved dictionary
# and fixes the ouput in order for it to be JSONable.
def yara_callback(data):
    global pe
    global filename
    # global rules_matched
    global sample_id
    global yara_matches_list
    global any_rules_matched

    rules_matched = False

    yara_match_entry = {}
    logging.info('Yara Match {}:'.format(data['rule']))

    yara_match_entry['matches'] = []
    yara_match_entry['rule'] = data['rule']

    for k in data['strings']:
        yara_match_entry['matches'].append({'offset': k[0], 'pattern': binascii.hexlify(k[2])})
        rules_matched = True

    if rules_matched:
        yara_matches_list.append(yara_match_entry)
        logging.info('[*] Matched: {}'.format(yara_match_entry))
        any_rules_matched = True

    yara.CALLBACK_CONTINUE


def get_ysa_strings(f_filename, imagebase=0):
    global string_dictionary
    global string_dictionary_by_name

    string_dict = list()
    current_offset = 0

    if imagebase is None:
        try:
            pe = pefile.PE(f_filename)
            imagebase = pe.OPTIONAL_HEADER.ImageBase
        except pefile.PEFormatError:
            imagebase = 0

    with open(f_filename, "rb") as f:
        current_offset += 1
        result = ""
        first_char = True
        offset = None

        for char in f.read():
            if first_char:
                offset = current_offset
                first_char = False

            try:
                if chr(char) in string.printable:
                    result += chr(char)
                    continue
            except TypeError:
                pass

            if len(result) >= 4:
                string_dict.append({'string': result, 'offset': imagebase + offset})

            result = ""
            first_char = True
            offset = None

    for line in string_dict:
        try:
            str_offset = int(line['offset'])
            str_string = line['string']

            found_str = {'str_content': '', 'str_offset': 0}
            found_str['str_offset'] = hex(str_offset)
            found_str['str_offset_calculated'] = hex(str_offset + imagebase)
            found_str['str_offset_little_endian'] = struct.pack('<L', str_offset + imagebase)
            found_str['str_content'] = str_string

            string_dictionary[found_str['str_offset_calculated']] = found_str
            string_dictionary_by_name[found_str['str_content']] = found_str

        except:
            logging.info('[!] got an empty line while processing strings... it\'s fine...')


def get_api_offets(f_filename, f_pe):
    global api_dictionary
    global api_dictionary_by_name

    try:
        for entry in f_pe.DIRECTORY_ENTRY_IMPORT:
            # print entry.dll
            for imp in entry.imports:
                imp_info = dict()
                # print '\t', hex(imp.address), imp.name
                imp_info['API'] = imp.name
                imp_info['str_offset_calculated'] = hex(imp.address)
                imp_info['str_offset_little_endian'] = struct.pack('<L', imp.address)
                api_dictionary[imp_info['str_offset_calculated']] = imp_info
                api_dictionary_by_name[imp_info['API']] = imp_info

    except:
        logging.info('[!] Could not load imports')


        # Check if IDC file for dump exists:
    if os.path.exists(f_filename + '.idc'):
        logging.info('[*] IDC For dump exits!')
        # Open the file, look for these entries:
        # MakeName(0x00626010, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
        # Add to it image base, then add to dictionaries
        with open(f_filename + '.idc', 'r') as f:
            for line in f:
                iat_entry = re.match('MakeName\((0x[A-F0-9]{8}), "(.+)"\)', line)
                if iat_entry:
                    addr_int = int(iat_entry.group(1), 16)
                    addr = hex(addr_int)
                    imp_name = iat_entry.group(2)

                    imp_info = {}
                    imp_info['API'] = imp_name
                    imp_info['str_offset_calculated'] = addr
                    imp_info['str_offset_little_endian'] = struct.pack('<L', addr_int)

                    # logging.info(imp_info)

                    api_dictionary[imp_info['str_offset_calculated']] = imp_info
                    api_dictionary_by_name[imp_info['API']] = imp_info


def disasm(f_filename, f_addr, f_max_opcodes, flag_64bit, stoponret):
    global api_dictionary
    global string_dictionary

    # Get the data at the physical offset
    f_data = get_data_at_offset(f_filename, f_addr)

    disasm_list = []
    start = 0
    op_count = 0

    data = binascii.hexlify(f_data)

    if flag_64bit:
        mode = distorm3.Decode64Bits
    else:
        mode = distorm3.Decode32Bits

    for o, _, i, h in distorm3.DecodeGenerator(start, data, mode):

        op_count += 1
        opcodes_decoded = i.decode('utf-8')
        if stoponret and opcodes_decoded.startswith("RET"):
            logging.info("Stopped at RET")
            disasm_list.append("RET")
            break

        if (op_count == f_max_opcodes):
            # logging.info("Stopped at max opcodes")
            break

        # Check if i (disassembly) is call/push of an offset:
        # CALL DWORD [0xed1e038]


        if flag_64bit:
            data_size = 'QWORD'
        else:
            data_size = 'DWORD'

        call_offset = re.match('CALL ' + data_size + ' \[(0x[a-f0-9]{2,8})\]', opcodes_decoded)

        push_offset = re.match('PUSH ' + data_size + ' (0x[a-f0-9]{2,8})', opcodes_decoded)

        if call_offset:
            logging.info("Call offset found: {}".format(call_offset.group(1)))
            # Now try to see if it any known string or offset
            if call_offset.group(1) in api_dictionary:
                logging.info('[*] is xref to API')
                i = re.sub(r'CALL ' + data_size + ' \[(0x[a-f0-9]{2,8})\]',
                           'CALL ' + api_dictionary[call_offset.group(1)]['API'], opcodes_decoded)
            elif call_offset.group(1) in string_dictionary:
                i = re.sub(r'CALL ' + data_size + ' \[(0x[a-f0-9]{2,8})\]',
                           'CALL ' + string_dictionary[call_offset.group(1)]['str_content'], opcodes_decoded)


        elif push_offset:
            logging.info("Push offset found: {}".format(push_offset.group(1)))
            if (push_offset.group(1) in api_dictionary):
                i = re.sub(r'PUSH ' + data_size + ' (0x[a-f0-9]{2,8})',
                           'PUSH ' + api_dictionary[push_offset.group(1)]['API'], opcodes_decoded)
            elif (push_offset.group(1) in string_dictionary):
                i = re.sub(r'PUSH ' + data_size + ' (0x[a-f0-9]{2,8})',
                           'PUSH ' + string_dictionary[push_offset.group(1)]['str_content'], opcodes_decoded)

        # oplen = len(h)
        # h = h.decode('utf-8') + ' ' * (16 - oplen)
        output_line = h.decode('utf-8') + ' ' + opcodes_decoded
        disasm_list.append(output_line)

    return disasm_list


def get_data_at_offset(f_filename, offset):
    with open(f_filename, 'rb') as f:
        f.seek(offset)
        data = f.read(1024)
        hex_data = binascii.hexlify(data)
        return hex_data


def hex_vaddr_2_paddr(f_hex_addr, f_pe):
    v_addr = int(f_hex_addr, 16)
    f_addr = (v_addr - f_pe.OPTIONAL_HEADER.ImageBase)
    return f_addr


def int_vaddr_2_paddr(f_int_addr, f_pe):
    f_addr = (f_int_addr - f_pe.OPTIONAL_HEADER.ImageBase)
    return f_addr


def int_paddr_2_vaddr(f_int_addr, f_pe):
    f_addr = (f_int_addr + f_pe.OPTIONAL_HEADER.ImageBase)
    return f_addr


# Generate the opcode pattern with the relevant offsets of API calls and strings
def get_dynamic_byte_code(f_pattern):
    global pe
    global filename
    global api_dictionary
    global string_dictionary

    error_found = False
    new_pattern = []
    for p in f_pattern:
        if (regex_pattern.match(p)):
            # print '%s is hex' % p
            new_pattern.append(p)
        elif (regex_pattern_wildcard.match(p)):
            new_pattern.append(p)
        else:
            operator = p.split(":", 2)
            if (operator[0] == 'string'):
                if (operator[1] in string_dictionary_by_name):
                    # logging.info(string_dictionary_by_name[operator[1]])
                    offset_for_yara = ' '.join(
                        binascii.hexlify(string_dictionary_by_name[operator[1]]['str_offset_little_endian'][i:i+1]).decode('utf-8') for i in
                        range(0, len(string_dictionary_by_name[operator[1]]['str_offset_little_endian']), 2))
                    # import ipdb; ipdb.set_trace()
                    new_pattern.append(offset_for_yara)
                else:
                    error_found = True
            elif (operator[0] == 'API'):
                if (operator[1] in api_dictionary_by_name):
                    # logging.info('[*] API Data: {}'.format(api_dictionary_by_name[operator[1]]))

                    offset_for_yara = ' '.join(
                        binascii.hexlify(api_dictionary_by_name[operator[1]]['str_offset_little_endian'][i:i+1]).decode('utf-8') for i in
                        range(0, len(api_dictionary_by_name[operator[1]]['str_offset_little_endian']), 2))
                    new_pattern.append(offset_for_yara)
                else:
                    error_found = True

    if error_found:
        return None

    return new_pattern


# Generate the YARA Rule, and execute it against the file provided
def generate_dynamic_rule(f_filename, f_rule_name, f_pattern):
    global pe
    global filename
    global api_dictionary
    global string_dictionary

    f_pattern_list = f_pattern.split()
    dyn_1 = get_dynamic_byte_code(f_pattern_list)
    if dyn_1 is None:
        # Could not find a match for this rule
        return

    if dyn_1[len(dyn_1)-1].endswith(']'):
        dyn_1.pop()
        logging.info('Removed last wildcard from rule, rule cannot end with wildcard')

    dyn_1_yara = " ".join(dyn_1)
    logging.info('[*] Dynamic bytecode for rule {}: {} '.format(f_rule_name, dyn_1))
    yara_output = """
    rule %s
    {
        meta:
            description = "%s"
    
        strings:
            $pattern = { %s }
    
        condition:
            $pattern
    }
    """ % (f_rule_name, f_rule_name, dyn_1_yara)
    try:
        rule_matches = False
        yara_results_list = list()
        rules = yara.compile(source=yara_output)
        yara_results = rules.match(f_filename)
        for match in yara_results:
            rule_matches = True
            rule_matches = list()
            for single_match in match.strings:
                rule_matches.append({'offset': hex(single_match[0]), 'condition': single_match[1], 'string': single_match[2].decode('utf-8', errors='ignore')})
            yara_results_list.append({'rule_name': match.rule, 'matches': rule_matches})
        if rule_matches:
            return yara_results_list
        return None
    except yara.SyntaxError as e:
        logging.error('Bad yara rule: {} : due to {}'.format(yara_output, e))


def semantically_analyze(sample_dump_instance):
    is_64bit = False

    f_filename = sample_dump_instance.binary_path
    pe = pefile.PE(sample_dump_instance.binary_path)

    logging.info('[*] Image Base: {}'.format(hex(pe.OPTIONAL_HEADER.ImageBase)))

    IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)

    # Check PE arch. if 0x10b then
    if (hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC):
        logging.info('[*] File is 32 bit')
    elif (hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC):
        logging.info('[*] File is 64 bit')
        is_64bit = True
    else:
        logging.info('[!] Could not determine architechture - guessing it is 32bit.')

    # Get IAT offsets
    get_api_offets(f_filename, pe)

    # Get strings
    get_ysa_strings(f_filename, pe.OPTIONAL_HEADER.ImageBase)

    # Load PE file
    logging.info('[*] Loading {}'.format(f_filename))
    pe = pefile.PE(f_filename)

    logging.info('[*] Image base: {} '.format(hex(pe.OPTIONAL_HEADER.ImageBase)))

    with open(SEMANTIC_YARA_RULES_PATH) as conf_file:
        data = json.load(conf_file)

    result = None
    yara_matches_list = list()
    for entry in data['yara_rules']:
        if is_64bit and entry['is_64bit'] == 'True':
            result = generate_dynamic_rule(f_filename, entry['rule_name'], entry['pattern'])

        elif not is_64bit and entry['is_64bit'] == 'False':
            result = generate_dynamic_rule(f_filename, entry['rule_name'], entry['pattern'])

        if result is not None:
            yara_matches_list.append(result)

    return yara_matches_list
