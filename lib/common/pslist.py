#! /usr/bin/python
import os
import yaml
import re
import subprocess
import pipes
import json

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
	f = open(VolatilityBot_Home + '/GoldenImage/' + vmname + '/pslist', 'r')
	pslist_GoldenImage = f.readlines()
	pslist_gi = []
	for line in pslist_GoldenImage:
	    splitted_line = re.split('\s+',  line.rstrip('\n'))  
	    if splitted_line[0].startswith("0x"):    
	        try:
		        entry = dict()
		        entry['offset'] = splitted_line[0]
		        entry['name'] = splitted_line[1]
		        entry['pid'] = splitted_line[2]
		        entry['ppid'] = splitted_line[3]
		        pslist_gi.append(entry)    
	        except:
	    		pass
	f.close()
	return pslist_gi

def get_new_pslist(mem,f_profile):
	global volatility_path
	command = volatility_path + ' --profile ' + f_profile + ' -f ' + mem + ' pslist'
	print command 
	proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
	pslist_run = []

	for line in iter(proc.stdout.readline, ''):
	    #Parse the line:
	    #0x8660c628 svchost.exe            1192    704      6       96      0      0 2015-01-19 19:29:44 UTC+0000                                 
	    #phy_addr,proc_name,pid,ppid,threads,Handles,sess,wow64,Start,Exit                    
	    splitted_line = re.split('\s+',  line.rstrip('\n'))  
	    if splitted_line[0].startswith("0x"):    
	        entry = dict()
	        entry['offset'] = splitted_line[0]
	        entry['name'] = splitted_line[1]
	        entry['pid'] = splitted_line[2]
	        entry['ppid'] = splitted_line[3]
	            
	        pslist_run.append(entry)
        return pslist_run


