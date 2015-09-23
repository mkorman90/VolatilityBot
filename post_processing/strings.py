# -*- coding: utf-8 -*-
"""
Created on Wed Feb 11 22:27:57 2015

@author: Martin
"""

import sys
import string
import json

printable = set(string.printable)

def process(filename):
    stream = open(filename, 'r+')
    found_str = ""
    offset_count = 0
    while True:
        data = stream.read(1024*4)
        offset_count = offset_count + (1024*4)
        if not data:
            break
        for char in data:
            if char in printable:
                found_str += char
            elif len(found_str) >= 6:
                entry = {}
                entry['offset'] = hex(offset_count - (len(found_str) * 4 * 1024))
                entry['string'] = found_str
                yield entry
                found_str = ""
            else:
                found_str = ""
                
                
def _run(filename,sample_id):
     string_list = []
     for found_str in process(filename):
        string_list.append(found_str)
     #print string_list
     json_output =  json.dumps(string_list, indent=4, sort_keys=True)
     return json_output

     
