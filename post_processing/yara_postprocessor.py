# -*- coding: utf-8 -*-
"""
Created on Wed Feb 11 23:02:36 2015

@author: Martin
"""

import os
import yaml
import yara
import json
from lib.core import DataBase

VolatilityBot_Home = ""
results_list = []
rules_matched = False
sample_id = ""

def _init():
  global VolatilityBot_Home
  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	VolatilityBot_Home = dataMap['mainconfig']['general']['VolatilityBot_Home']

def showdata(data):
  global sample_id 
  global rules_matched
  #print data
  #results_list.append(json.dumps(data, indent=4, sort_keys=True))
  if (data["matches"]):  
      rules_matched = True
      #unicode('\x80abc', errors='replace')
      single_match = {}
      single_match['rule'] = data['rule']
      single_match['strings'] = []
      for k in data['strings']:
          for s_string in k:
              entry = []
              entry.append(unicode(str(s_string), errors='replace'))
          single_match['strings'].append(entry)
      results_list.append(single_match)
      DataBase.add_tag(data["rule"],sample_id)
  yara.CALLBACK_CONTINUE

def _run(filename,f_sample_id):
    _init()
    global sample_id
    sample_id = f_sample_id
    yarfile = VolatilityBot_Home + '/conf/yara_rules.yar'
    print "[*] Loaded .yar file: %s" % (yarfile)
    rules = yara.compile(yarfile)
    matches = rules.match(filename,callback=showdata)
    #print results_list
    json_output =  json.dumps(results_list, indent=4, sort_keys=True)
    #print json_output
    if (rules_matched):
        return json_output
    else:
        return "none"
    




