#! /usr/bin/python
import re
import pefile
import yara
import sys
import os
import string
import struct
import json
import binascii
import pefile
import sys

sys.path.append('/home/martin/MWA/VolatilityBot/volatilitybot')

from lib.core import DataBase



#Dynamic YARA rules generator for PE files
#Generate dynamic YARA bytecode signatures for code patterns in PE files:
#Besides signing regular opcodes, string and API options let you get the offset of 
#A string or an API call inside the PE file, and add it as a variable generated from the PE file
#Directly inside the YARA Signature:
#Currently supported:
#   string:Example.com       ----> Will look for the string in memory, and calculate the address (Pe image base + offset)
#   API:CreateRemoteThread   ----> Will go over the IAT and find the address of the import. 
#Offsets returned will be put instead of that place holder.
#The resulting patterns will be ran against the PE file supplied as a parameter


printable = set(string.printable)
regex_pattern = re.compile("^([A-F0-9]{2})$")
regex_pattern_wildcard = re.compile("^(\[\d{1,3}\])$")
api_dictionary = {}
string_dictionary = {}
yara_matches_list = []
rules_matched = False


#Callback for YARA signatures - Processes the recieved dictionary 
#and fixes the ouput in order for it to be JSONable.
def yara_callback(data):
  global pe
  global filename
  global rules_matched
  global sample_id
  
  
  
  yara_match_entry = {} 
  print 'Yara Match %s:' % (data['rule'])
  
  yara_match_entry['matches'] = []
  yara_match_entry['rule'] = data['rule']

  DataBase.add_tag(data["rule"],sample_id)  

  
  for k in data['strings']:
      yara_match_entry['matches'].append({'offset' : hex(k[0]), 'pattern' : binascii.hexlify(k[2])})
      rules_matched = True
  
  yara_matches_list.append(yara_match_entry)  
  yara.CALLBACK_CONTINUE

#Extract strings, and return a dictionary with string and offset from image base.
def get_strings(filename):
    global pe
    
    stream = open(filename, 'r+')
    found_str = {'str_content' : '', 'str_offset' : 0}
    offset = 0
    while True:
        data = stream.read(1024*4)
        if not data:
            break
        
        first_char = True
        for char in data:
            if char in printable:
                if (first_char):
                    first_char = False
                    found_str['str_offset'] = hex(offset)
                    found_str['str_offset_calculated'] = hex(offset + pe.OPTIONAL_HEADER.ImageBase)
                    found_str['str_offset_little_endian'] = struct.pack('<L', offset + pe.OPTIONAL_HEADER.ImageBase).encode('hex')

                    
                found_str['str_content'] += char
            elif len(found_str['str_content']) >= 4:
                yield found_str
                first_char = True
                found_str = {'str_content' : '', 'str_offset' : 0}
            else:
                found_str = {'str_content' : '', 'str_offset' : 0}
                first_char = True
            offset = offset + 1
                
#Return a dictionary item of API calls and their call address
def get_api_offets():
    global pe
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
          #print entry.dll
          for imp in entry.imports:
            imp_info = {}
            #print '\t', hex(imp.address), imp.name
            imp_info['API']  = imp.name
            imp_info['str_offset_calculated'] = hex(imp.address)
            imp_info['str_offset_little_endian']  = struct.pack('<L', imp.address).encode('hex')
            yield imp_info
    
    except:
        print '[!] Could not load imports'    

#Generate the opcode pattern with the relevant offsets of API calls and strings
def get_dynamic_byte_code(f_pattern):
    global pe
    global filename
    
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
                if (operator[1] in string_dictionary):
                    print string_dictionary[operator[1]]
                    offset_for_yara = ' '.join(string_dictionary[operator[1]]['str_offset_little_endian'][i:i+2] for i in range(0, len(string_dictionary[operator[1]]['str_offset_little_endian']), 2))
                    new_pattern.append(offset_for_yara)
                else:
                    error_found = True
            elif (operator[0] == 'API'):
                 if (operator[1] in api_dictionary):
                    print '[*] API Data: %s' % api_dictionary[operator[1]]
                    offset_for_yara = ' '.join(api_dictionary[operator[1]]['str_offset_little_endian'][i:i+2] for i in range(0, len(api_dictionary[operator[1]]['str_offset_little_endian']), 2))
                    new_pattern.append(offset_for_yara)  
                 else:
                     error_found = True    
                     
    if (error_found):
        return 'failed'
    
    return new_pattern
        

#Generate the YARA Rule, and execute it against the file provided
def generate_dynamic_rule(f_rule_name,f_pattern):
    global pe
    global filename
    
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
    matches = rules.match(filename,callback=yara_callback)




def _run(f_filename,f_sample_id):
    global pe
    global filename
    global sample_id
    
    filename = f_filename
    sample_id = f_sample_id
    
    #Load PE file
    print 'Loading %s' % f_filename
    pe =  pefile.PE(f_filename)
    
    #Generate strings dictionary
    for found_str_pattern in get_strings(f_filename):
        #print found_str_pattern
        string_dictionary[found_str_pattern['str_content']] = found_str_pattern
    
    #Generate API Calls dictionary
    for found_api in get_api_offets():
        #print found_api
        api_dictionary[found_api['API']] = found_api

    with open('conf/Semantic_Rules.json') as conf_file:    
        data = json.load(conf_file)
      
    for entry in  data['yara_rules']:
        generate_dynamic_rule(entry['rule_name'],entry['pattern'])
        
    
    print '[*] YARA Matches: %s' % json.dumps(yara_matches_list,indent=4)
    
    if (rules_matched):
        json_output =  json.dumps(yara_matches_list, indent=4, sort_keys=True)
        print json_output
        return json_output
    else:
        return "none"
        
    






                
    






