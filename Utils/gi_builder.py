#! /usr/bin/python
import os
import yaml
import pipes
import threading
import importlib
import time
import pefile
import argparse
from time import gmtime, strftime
from datetime import datetime
from threading import Thread
import threading
import shutil
import subprocess


from lib.core import CodeExtractor




vmindex = []
global vmindex
global lock_vmindex 
lock_vmindex = {}

global vm_comm_lock
vm_comm_lock = threading.Lock()

vmrun_path = ""
VolatilityBot_Home = ""
machine_type = ""

modules_list = []
active_pools = []

def read_config():
	global vmindex
	global lock_vmindex
	global vmrun_path
	global VolatilityBot_Home
	global machine_type
	global volatility_path
	global active_pools
 
	config_file_path = './conf/main.conf'

	if os.path.isfile(config_file_path):
		f = open(config_file_path)
		# use safe_load instead load
		dataMap = yaml.safe_load(f)
		f.close()
		#print dataMap
  
		VolatilityBot_Home  = pipes.quote(dataMap['mainconfig']['general']['VolatilityBot_Home'])
		machine_type = dataMap['mainconfig']['general']['machine_type']	
		volatility_path  = pipes.quote(dataMap['mainconfig']['general']['volatility_path'])  
		active_pools = dataMap['mainconfig']['general']['active_pools'].split(',')
  
  
		return True
	else:
		print "[*] %s is not a file, or not found." % (config_file_path)
		return False




global init_machine
global revert
global start
global suspend
global get_mem_path
global modules_list    
global cleanup
global active_pools
global volatility_path


read_config()

machine_engine = importlib.import_module('machines.' + machine_type,machine_type)
init_machine = getattr(machine_engine,'_init')
revert = getattr(machine_engine,'_revert')
start = getattr(machine_engine,'_start')
suspend = getattr(machine_engine,'_suspend')
get_mem_path = getattr(machine_engine,'_get_mem_path')
cleanup = getattr(machine_engine,'_cleanup')

modules_list = CodeExtractor._load_config()

vmindex = init_machine()

global lock_vmindex 
lock_vmindex = {}   
for pool in active_pools:     
    for vm in vmindex[pool]:
        print "[*] VM name: %s Enabled: %s" % (vm['name'],vm['enabled'])
        if vm['enabled']:
            print '  [*] Creating Golden image for this machine!'
            print "[*] Reverting Machine..."
            revert(vm) 
            start(vm)
            print "[*] Sleeping 10 seconds..."
            time.sleep(10)
            print "[*] Suspending Machine..."
            suspend(vm)
            print "[*] Acquiring memory..."        
            vmem_path =  get_mem_path(vm)
        
            gi_dir = VolatilityBot_Home + '/GoldenImage/' + vm['name']        
            
            
            if os.path.exists(gi_dir):
                print "[*] Folder already exists, deleting and recreating"        
                shutil.rmtree(gi_dir)
                os.mkdir(gi_dir)
            else:
                print "[*] Folder does not exist, recreating"                    
                os.mkdir(gi_dir)
            
            print "[*] Executing Golden Image modules"                    
            
            modules = ['pslist','dlllist','ldrmodules','modscan']
            for mod in modules:
                 command = volatility_path + ' --profile ' + vm['profile'] + ' -f ' + vmem_path + ' --output=json ' + mod
                 print command
                 proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
                 print '[*] Executing ' + mod
                 output = proc.stdout.read()
                 
                 #Write output to file
                 obj = open(gi_dir + '/' + mod, 'wb')
                 obj.write(output)                
                 obj.close  
                 
                
            print "[*] Done for Machine: %s" % (vm['name'])
    
print "[*] Done. Enjoy! "
    
    
    
    
    
    
    
    
    
    