#! /usr/bin/python
import os
import yaml
import pipes
import subprocess
import logging
import json

vmindex = []
vmrun_path = ""
gui = ""

def _load_config():
  global vmrun_path
  global gui  
  global machines_log_path  
  if os.path.isfile('conf/vmware.conf'):
	f = open('conf/vmware.conf')
	# use safe_load instead load
	dataMap = json.load(f)
	f.close()

	vmrun_path_tmp = dataMap['general']['vmrun_path']
  	vmrun_path = vmrun_path_tmp.replace(' ','\\ ')
   
  if (dataMap['general']['gui']):
    gui = "gui"     
	
  return True       
 
  
def _init():
  machine_count = 0
  global vmrun_path
  global gui
  
  print "[*] [vmware] Loading vmware module"    
  logging.info("[*] [vmware] Loading vmware module")
  
  if os.path.isfile('conf/vmware.conf'):
	f = open('conf/vmware.conf')
	# use safe_load instead load
	dataMap = json.load(f)
	f.close()


  #print json.dumps(dataMap,indent=4)
  vmrun_path_tmp = dataMap['general']['vmrun_path']
  vmrun_path = vmrun_path_tmp.replace(' ','\\ ')
  gui = dataMap['general']['gui']
 
  pool_index = {} 
 
  for res_pool in dataMap['general']['machine_resource_pools']:
      if dataMap['general']['machine_resource_pools'][res_pool]['active']:
          print '[*] Loading Machine Resouce Pool: %s' % res_pool
          pool_index[res_pool] = []
          for vm_cfg in dataMap['general']['machine_resource_pools'][res_pool]['machines']:
             vm = {}
             vm['enabled']       = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['enabled']
             vm['name'] 			   = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['name']
             vm['vmx_path'] 		 = pipes.quote(dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['vmx_path'])
             vm['vmdk_path'] 		 = pipes.quote(dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['vmdk_path'])
             vm['IP'] 				   = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['IP']
             vm['snapshot_name'] = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['snapshot_name']
             vm['status'] 			 = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['status']
             vm['profile']       = dataMap['general']['machine_resource_pools'][res_pool]['profile'] 
             if (vm['enabled']):
                 machine_count  = machine_count + 1
    
             pool_index[res_pool].append(vm)
    					
             print " - Loaded machine - %s" % (vm['name'])
             logging.info(" - Loaded machine - %s" % (vm['name']))
              
              
              
      else:
         print '[!] Inactive Machine Resouce Pool: %s' % res_pool     
          
  #print json.dumps(pool_index,indent=4)
 
			
  print "[*] [vmware] Active machines: %d" % (machine_count) 
  logging.info("[*] [vmware] Active machines: %d" % (machine_count) )
  
 
 
  return pool_index 


def _revert(vm):
    _load_config()
    print "[*] [%s] Reverting to snapshot %s:" % (vm['name'],vm['snapshot_name'])
    logging.info("[*] [%s] Reverting to snapshot %s:" % (vm['name'],vm['snapshot_name']))
    command = vmrun_path + " revertToSnapshot " + vm['vmx_path'] + " " + vm['snapshot_name']
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    if output:
        print "[!] [%s] Error when starting VM: %s" % (vm['name'],output)
        logging.info("[!] [%s] Error when starting VM: %s" % (vm['name'],output))
        return False
    
    return True

def _start(vm):
    _load_config()
    print "[*] [%s] Starting VM" % (vm['name'])    
    logging.info("[*] [%s] Starting VM" % (vm['name']))
    command = vmrun_path + " start " +  vm['vmx_path']
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    if output:
        print "[!] [%s] Error when starting VM: %s" % (vm['name'],output)
        logging.info("[!] [%s] Error when starting VM: %s" % (vm['name'],output))
        return False
    
    return True

def _suspend(vm):
    _load_config()
    print " [*] [%s] Suspending VM" % (vm['name'])
    logging.info("[*] [%s] Suspending VM" % (vm['name']))
    command = vmrun_path + " suspend " +  vm['vmx_path'] + " hard"
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    if output:
        print "[!] [%s] Error when suspending: %s" % (vm['name'],output)
        logging.info("[!] [%s] Error when suspending: %s" % (vm['name'],output))
        return False
    
    return True
    """
    try:
        print "%s %s %s" % (vmrun_path,"suspend",vm['vmx_path'])
        if subprocess.call([vmrun_path,"suspend",vm['vmx_path']," hard"],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE):        
                           raise "Unable to revert snapshot for %s " % (vm['name'])
    except:
        print "Unable to suspend VM: %s" % (vm['name'])  
    """ 
def _get_mem_path(vm):    
	command = '/bin/ls -tr ' + vm['vmdk_path'] + '*.vmem | tail -1'
	proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
	snapshot_name = proc.stdout.read()
	snapshot_name = snapshot_name.strip()
	snapshot_name = snapshot_name.replace(' ','\\ ')
	print "[*] [%s] Got Snapshot name: %s" % (vm['name'],snapshot_name)
 	logging.info("[*] [%s] Got Snapshot name: %s" % (vm['name'],snapshot_name))
	return snapshot_name    
    
    
def _cleanup(vm):
    print "[*] [%s] Cleanup done." % (vm['name'])
    logging.info("[*] [%s] Cleanup done." % (vm['name']))
    return True
     