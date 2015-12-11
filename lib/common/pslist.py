#! /usr/bin/python
import os
import yaml
import json

import re
import subprocess
import pipes
from string import join

VolatilityBot_Home = ""
volatility_path = ""

def hi():
	print "hi!"

def _load_config():
  global VolatilityBot_Home
  global volatility_path
  
  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	VolatilityBot_Home = dataMap['mainconfig']['general']['VolatilityBot_Home']
	volatility_path  = pipes.quote(dataMap['mainconfig']['general']['volatility_path'])  
         
	return True       
 
  return False
    
def load_golden_image(vmname):
    	_load_config()
	#f = open(VolatilityBot_Home + '/GoldenImage/' + vmname + '/pslist', 'r')
	#pslist_GoldenImage = f.readlines()

	with open(VolatilityBot_Home + '/GoldenImage/' + vmname + '/pslist') as data_file:    
         pslist_GoldenImage = json.load(data_file)
    
	pslist_gi = []
         
	"""
                "Offset(V)",
                "Name",
                "PID",
                "PPID",
                "Thds",
                "Hnds",
                "Sess",
                "Wow64",
                "Start",
                "Exit"
	"""         
         
	for proc in pslist_GoldenImage['rows']:
         _load_config()
         entry = dict()
         try:
             entry = dict()
             entry['offset'] = "0x%x" % proc[0]
             entry['name'] = proc[1]
             entry['pid'] = proc[2]
             entry['ppid'] = proc[3]
             pslist_gi.append(entry)    
         except:
             pass         
 
	return pslist_gi

def get_new_pslist(mem,f_profile):
	global volatility_path
	_load_config()
	command = volatility_path + ' --profile ' + f_profile + ' -f ' + mem + ' pslist --output=json '
	print '[DEBUG]:' + command 
	proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
	pslist_run = []

	output_list = proc.stdout.readlines()
	output = join(output_list, "") 
	pslist_new_from_machine = json.loads(output)
	for line in pslist_new_from_machine['rows']:               
         entry = dict()
         entry['offset'] = "0x%x" % line[0]
         entry['name'] = line[1]
         entry['pid'] = line[2]
         entry['ppid'] = line[3]
	            
         pslist_run.append(entry)
	return pslist_run

