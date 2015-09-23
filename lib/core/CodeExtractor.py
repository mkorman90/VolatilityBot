#! /usr/bin/python
import yaml
import os

module_list = []

def _load_config():
  global module_list

  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	mod_arr = dataMap['mainconfig']['general']['modules']
	for module in mod_arr.split(','):
         print "[*] Loaded Module: %s" % (module)
         module_list.append(module)


	 
	return module_list       
 
  return module_list