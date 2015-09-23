import distorm3
import os
import binascii
import re
import pefile
import struct
import string
import json
import yara
import sys
from subprocess import PIPE,Popen
sys.path.append('/home/martin/MWA/VolatilityBot/volatilitybot')

from lib.core import DataBase



printable = set(string.printable)


api_dictionary = {}
string_dictionary = {}

api_dictionary_by_name = {}
string_dictionary_by_name = {}


yara_matches_list = []

any_rules_matched = False

regex_pattern = re.compile("^([A-F0-9]{2})$")
regex_pattern_wildcard = re.compile("^(\[(\d{1,3}|\-)\])$")



#Callback for YARA signatures - Processes the recieved dictionary 
#and fixes the ouput in order for it to be JSONable.
def yara_callback(data):
  global pe
  global filename
  #global rules_matched
  global sample_id
  global yara_matches_list
  global any_rules_matched
  
  
  rules_matched = False  
  
  yara_match_entry = {} 
  print 'Yara Match %s:' % (data['rule'])
  
  yara_match_entry['matches'] = []
  yara_match_entry['rule'] = data['rule']

  #DataBase.add_tag(data["rule"],sample_id)  

  
  for k in data['strings']:
      yara_match_entry['matches'].append({'offset' : k[0], 'pattern' : binascii.hexlify(k[2])})
      rules_matched = True
  
  if rules_matched:
      yara_matches_list.append(yara_match_entry)  
      print '[*] Matched: %s' % yara_match_entry
      any_rules_matched = True
      
  yara.CALLBACK_CONTINUE

def get_strings(f_filename,f_pe):
    global string_dictionary
    global string_dictionary_by_name

    #Get unicode strings
    #results_unicode = subprocess.check_output(['strings', '--encoding=l','--radix=d', f_filename]).splitlines()
    
    
    proc = Popen(['strings', '--encoding=l','--radix=d', f_filename], stdout=PIPE)
    results_unicode = proc.communicate()[0].splitlines()

    
    for line in results_unicode:
        try:
            arr = line.split()
            str_offset =  int(arr[0])
            str_string =  arr[1]
            
            found_str = {'str_content' : '', 'str_offset' : 0}
            found_str['str_offset'] = hex(str_offset)
            found_str['str_offset_calculated'] = hex(str_offset + f_pe.OPTIONAL_HEADER.ImageBase)
            found_str['str_offset_little_endian'] = struct.pack('<L', str_offset + f_pe.OPTIONAL_HEADER.ImageBase).encode('hex')        
            found_str['str_content'] = str_string
            
            string_dictionary[found_str['str_offset_calculated']] = found_str
            string_dictionary_by_name[found_str['str_content']] = found_str        

        except:
            print '[!] got an empty line while processing strings... it\'s fine...'

    #Get regular strings (Classic C)
    #results_reg = subprocess.check_output(['strings','--radix=d', f_filename]).splitlines()
    proc = Popen(['strings','--radix=d', f_filename], stdout=PIPE)
    results_reg = proc.communicate()[0].splitlines()
    
    for line in results_reg:
        try:
            arr = line.split()
            str_offset =  int(arr[0])
            str_string =  arr[1]
            
            found_str = {'str_content' : '', 'str_offset' : 0}
            found_str['str_offset'] = hex(str_offset)
            found_str['str_offset_calculated'] = hex(str_offset + f_pe.OPTIONAL_HEADER.ImageBase)
            found_str['str_offset_little_endian'] = struct.pack('<L', str_offset + f_pe.OPTIONAL_HEADER.ImageBase).encode('hex')        
            found_str['str_content'] = str_string
            
            string_dictionary[found_str['str_offset_calculated']] = found_str
            string_dictionary_by_name[found_str['str_content']] = found_str     
        except:
            print '[!] got an empty line while processing strings... it\'s fine...'
    



def get_api_offets(f_filename,f_pe):
    global api_dictionary
    global api_dictionary_by_name
    
    try:
        for entry in f_pe.DIRECTORY_ENTRY_IMPORT:
          #print entry.dll
          for imp in entry.imports:
            imp_info = {}
            #print '\t', hex(imp.address), imp.name
            imp_info['API']  = imp.name
            imp_info['str_offset_calculated'] = hex(imp.address)
            imp_info['str_offset_little_endian']  = struct.pack('<L', imp.address).encode('hex')
            api_dictionary[imp_info['str_offset_calculated']] = imp_info
            api_dictionary_by_name[imp_info['API']] = imp_info
    
    except:
        print '[!] Could not load imports'   
    
    
    #Check if IDC file for dump exists:
    if (os.path.exists(f_filename + '.idc')):
        print '[*] IDC For dump exits!'
        #Open the file, look for these entries:
        #MakeName(0x00626010, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
        #Add to it image base, then add to dictionaries
        with open(f_filename + '.idc','r') as f: 
            for line in f:
                iat_entry = re.match('MakeName\((0x[A-F0-9]{8}), "(.+)"\)',line)
                if iat_entry:
                    addr_int = int(iat_entry.group(1),16)
                    addr = hex(addr_int)
                    imp_name = iat_entry.group(2)
                    
                    imp_info = {}
                    imp_info['API']  = imp_name
                    imp_info['str_offset_calculated'] = addr
                    imp_info['str_offset_little_endian']  = struct.pack('<L', addr_int).encode('hex')
                    
                    print imp_info                    
                    
                    api_dictionary[imp_info['str_offset_calculated']] = imp_info
                    api_dictionary_by_name[imp_info['API']] = imp_info
                    
                    


def disasm(f_filename,f_addr,f_max_opcodes,flag_64bit,stoponret):
    global api_dictionary
    global string_dictionary
    

    #Get the data at the physical offset
    f_data = get_data_at_offset(f_filename,f_addr)    
    
    disasm_list = []
    start = 0
    op_count = 0
    
    data = f_data.decode("hex")
    
    if flag_64bit:
        mode = distorm3.Decode64Bits
    else:
        mode = distorm3.Decode32Bits        
    
    for o, _, i, h in distorm3.DecodeGenerator(start, data, mode):
        
        op_count = op_count + 1
        
        if stoponret and i.startswith("RET"):
            print "Stopped at RET"
            disasm_list.append("RET")            
            break
        
        if (op_count == f_max_opcodes):
            print "Stopped at max opcodes"
            break
        
        #Check if i (disassembly) is call/push of an offset:
        #CALL DWORD [0xed1e038]

        
        if (flag_64bit):
            data_size = 'QWORD'
        else:
            data_size = 'DWORD'
        
        call_offset = re.match('CALL ' + data_size + ' \[(0x[a-f0-9]{2,8})\]', i)
        
        push_offset = re.match('PUSH ' + data_size + ' (0x[a-f0-9]{2,8})', i)
        
        if call_offset:
          print "Call offset found: ",call_offset.group(1)
          #Now try to see if it any known string or offset
          if (call_offset.group(1) in api_dictionary):
              print '[*] is xref to API'
              i = re.sub (r'CALL ' + data_size + ' \[(0x[a-f0-9]{2,8})\]', 'CALL ' + api_dictionary[call_offset.group(1)]['API'] , i)
          elif (call_offset.group(1) in string_dictionary):
              i = re.sub (r'CALL ' + data_size + ' \[(0x[a-f0-9]{2,8})\]', 'CALL ' + string_dictionary[call_offset.group(1)]['str_content'] , i)
          
          
        elif push_offset:
          print "Push offset found: ",push_offset.group(1)             
          if (push_offset.group(1) in api_dictionary):
              i = re.sub (r'PUSH ' + data_size + ' (0x[a-f0-9]{2,8})', 'PUSH ' + api_dictionary[push_offset.group(1)]['API'] , i)
          elif (push_offset.group(1) in string_dictionary):
              i = re.sub (r'PUSH ' + data_size + ' (0x[a-f0-9]{2,8})', 'PUSH ' + string_dictionary[push_offset.group(1)]['str_content'] , i)
              
        
        oplen = len(h)
        h = h + ' ' * (16 - oplen)
        
        output_line = h + i  
        
        #print output_line
        
        disasm_list.append(output_line)
    
    return disasm_list
        


def get_data_at_offset(f_filename,offset):
    with open(f_filename, 'r') as f:    
        f.seek(offset)
        data = f.read(1024)
        hex_data = binascii.hexlify(data)    
        return hex_data


def hex_vaddr_2_paddr(f_hex_addr,f_pe):
    v_addr = int(f_hex_addr,16)
    f_addr = (v_addr - f_pe.OPTIONAL_HEADER.ImageBase)     
    return f_addr

def int_vaddr_2_paddr(f_int_addr,f_pe):
    f_addr = (f_int_addr - f_pe.OPTIONAL_HEADER.ImageBase)     
    return f_addr

def int_paddr_2_vaddr(f_int_addr,f_pe):
    f_addr = (f_int_addr + f_pe.OPTIONAL_HEADER.ImageBase)     
    return f_addr    

#Generate the opcode pattern with the relevant offsets of API calls and strings
def get_dynamic_byte_code(f_pattern):
    global pe
    global filename
    global api_dictionary
    global string_dictionary
    
    error_found = False
    new_pattern = []
    for p in f_pattern:
        if (regex_pattern.match(p)):
            #print '%s is hex' % p
            new_pattern.append(p)
        elif (regex_pattern_wildcard.match(p)):
            new_pattern.append(p)
        else:
            operator = p.split(":", 2)
            print 'op: %s, parameter %s' % (operator[0],operator[1])
            if (operator[0] == 'string'):
                if (operator[1] in string_dictionary_by_name):
                    print string_dictionary_by_name[operator[1]]
                    offset_for_yara = ' '.join(string_dictionary_by_name[operator[1]]['str_offset_little_endian'][i:i+2] for i in range(0, len(string_dictionary_by_name[operator[1]]['str_offset_little_endian']), 2))
                    new_pattern.append(offset_for_yara)
                else:
                    error_found = True
                    print '[!] Could not find string: %s' % operator[1]
            elif (operator[0] == 'API'):
                 if (operator[1] in api_dictionary_by_name):
                    print '[*] API Data: %s' % api_dictionary_by_name[operator[1]]
                    offset_for_yara = ' '.join(api_dictionary_by_name[operator[1]]['str_offset_little_endian'][i:i+2] for i in range(0, len(api_dictionary_by_name[operator[1]]['str_offset_little_endian']), 2))
                    new_pattern.append(offset_for_yara)  
                 else:
                     error_found = True    
                     print '[!] Could not find API: %s' % operator[1]
                     
    if (error_found):
        return 'failed'
    
    return new_pattern
        

#Generate the YARA Rule, and execute it against the file provided
def generate_dynamic_rule(f_filename,f_rule_name,f_pattern):
    global pe
    global filename
    global api_dictionary
    global string_dictionary
    
    f_pattern_list = f_pattern.split()
    dyn_1 = get_dynamic_byte_code(f_pattern_list)
    if (dyn_1 == 'failed'):
        print '[!] Could not fill prequisites of rule %s' % f_rule_name
        return
        
    dyn_1_yara = " ".join(dyn_1)
    print '[*] Dynamic bytecode for rule %s: %s ' % (f_rule_name,dyn_1)
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
    """ % (f_rule_name,f_rule_name,dyn_1_yara)
    
    #print '[*] Generated yara rule: %s' % yara_output
    
    #print '[*] Testing rule vs. PE file:'
    
    rules = yara.compile(source=yara_output)
    matches = rules.match(f_filename,callback=yara_callback)


    

def _run(f_filename,f_sample_id):
    
    is_64bit = False

    pe =  pefile.PE(f_filename)
    
    print '[*] Image Base: %s' % hex(pe.OPTIONAL_HEADER.ImageBase)
    
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)

    #Check PE arch. if 0x10b then     
    print '[*] Magic: %s' % hex(pe.OPTIONAL_HEADER.Magic)
    if (hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC):
        print '[*] File is 32 bit'
    elif (hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC): 
        print '[*] File is 64 bit'
        is_64bit = True
    else:
        print '[!] Could not determine architechture - guessing it is 32bit.'
        
    
    
    
    #Get IAT offsets
    get_api_offets(f_filename,pe)
    #print api_dictionary
    
    #Get strings
    get_strings(f_filename,pe)
    #for it in string_dictionary:
    #    print string_dictionary[it]


    #Load PE file
    print '[*] Loading %s' % f_filename
    pe =  pefile.PE(f_filename)
    
    print '[*] Image base: %s ' % hex(pe.OPTIONAL_HEADER.ImageBase)
    

    with open('conf/Semantic_Rules.json') as conf_file:    
        data = json.load(conf_file)
      
    for entry in  data['yara_rules']:
        if (is_64bit and entry['is_64bit'] == 'True'):
            generate_dynamic_rule(f_filename,entry['rule_name'],entry['pattern'])
        elif (not is_64bit and entry['is_64bit'] == 'False'):
            generate_dynamic_rule(f_filename,entry['rule_name'],entry['pattern'])
        
    
    #print '[*] YARA Matches: %s' % json.dumps(yara_matches_list,indent=4)

    results_list = {}
    for match in yara_matches_list:
        
        DataBase.add_tag(match['rule'],f_sample_id) 
        
        results_list[match['rule']] = []
        entry = {}
        
        for pattern_match in match['matches']:
            entry['offset'] = hex(int_paddr_2_vaddr(pattern_match['offset'],pe))
            
            disasm_string =  disasm(f_filename,pattern_match['offset'],32,is_64bit,True)
            
            #print '[DEBUG] %s' % disasm_string
            
            matching_disasm = []
            for line in disasm_string:
                matching_disasm.append(line)
            
            entry['Disassembly'] = matching_disasm
            
        results_list[match['rule']].append(entry)   

            
            
            
    
    
    
    if (any_rules_matched):
        json_output =  json.dumps(results_list, indent=4, sort_keys=True)
        return json_output
    else:
        return "none"
        
    
#f_filename = '/home/martin/Dropbox/Projects/SemanticYara/Dyres/0x437.exe'

#f_filename = 'Store/ff0da2495a9ff0276ca38a1144693b5c641a6ac6c1b980cf447b0d419c3f5f34/78HXND/cmd.exe.3364._exe'

"""

f_filename = sys.argv[1]

json_output_ysa = _run(f_filename,6666)

print json_output_ysa
"""


"""

#Get entrypoint
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print '[*] EP: %s' % str(hex(ep))


#Get the physical address, from the virtual one
#Hex address:
addr = hex_vaddr_2_paddr('0xF9AF45',pe)

#Int address:
#addr = int_vaddr_2_paddr(16363333,pe)




#Disassemble that data (filename,physical_offset,number_of_opcodes,64bit?,return_on_RET)
disasm_string =  disasm(f_filename,addr,32,False,True)

"""    
    