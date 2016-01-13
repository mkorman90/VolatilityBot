#! /usr/bin/python
import os
import yaml
import pipes
import subprocess
import logging
import json

from pysphere import VIServer


vmindex = []
vmrun_path = ""
gui = ""

ESX_SERVER = ''
ESX_USERNAME = ''
ESX_PASSWORD = ''

def _load_config():
  global vmrun_path
  global gui  
  global machines_log_path  
  global ESX_SERVER
  global ESX_USERNAME
  global ESX_PASSWORD


  if os.path.isfile('conf/esx.conf'):
	f = open('conf/esx.conf')
	# use safe_load instead load
	dataMap = json.load(f)
	f.close()


  ESX_SERVER = dataMap['general']['esx_server']
  ESX_USERNAME = dataMap['general']['esx_username']
  ESX_PASSWORD = dataMap['general']['esx_password']


	
  return True       
 
  
def _init():
  machine_count = 0
  global vmrun_path
  global gui
  global ESX_SERVER
  global ESX_USERNAME
  global ESX_PASSWORD

  print "[*] [vmware] Loading vmware module"    
  logging.info("[*] [vmware] Loading vmware module")
  
  if os.path.isfile('conf/esx.conf'):
	f = open('conf/esx.conf')
	# use safe_load instead load
	dataMap = json.load(f)
	f.close()

  ESX_SERVER = dataMap['general']['esx_server']
  ESX_USERNAME = dataMap['general']['esx_username']
  ESX_PASSWORD = dataMap['general']['esx_password']


  server = VIServer()
  server.connect(ESX_SERVER, ESX_USERNAME, ESX_PASSWORD)

  pool_index = {} 
 
  for res_pool in dataMap['general']['machine_resource_pools']:
      if dataMap['general']['machine_resource_pools'][res_pool]['active']:
          print '[*] Loading Machine Resouce Pool: %s' % res_pool
          pool_index[res_pool] = []
          for vm_cfg in dataMap['general']['machine_resource_pools'][res_pool]['machines']:
             vm = {}
             vm['enabled']                       = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['enabled']
             vm['name'] 			                   = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['name']
             vm['vmx_path'] 		                 = pipes.quote(dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['vmx_path'])
             vm['vmdk_path'] 		                 = pipes.quote(dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['vmdk_path'])
             vm['IP'] 				                   = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['IP']
             vm['snapshot_name']                 = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['snapshot_name']
             vm['status'] 			                 = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['status']
             vm['profile']                       = dataMap['general']['machine_resource_pools'][res_pool]['profile'] 
             vm['datastore']                     = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['datastore']
             vm['path_of_vmx_on_esx']            = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['path_of_vmx_on_esx']
             if (vm['enabled']):
                 machine_count  = machine_count + 1

                 vm_handle = server.get_vm_by_name(vm['name'])
                 print dir(vm_handle)
                 #vm_status = vm_handle.get_status() #POWERED ON
                 #print vm_status
    
             pool_index[res_pool].append(vm)
    					
             print " - Loaded machine - %s" % (vm['name'])
             logging.info(" - Loaded machine - %s" % (vm['name']))
              

             #vms = server.get_registered_vms()
             #for vm in vms:
              #print vm
              
              
      else:
         print '[!] Inactive Machine Resouce Pool: %s' % res_pool     
          
  #print json.dumps(pool_index,indent=4)
 
			
  print "[*] [vmware] Active machines: %d" % (machine_count) 
  logging.info("[*] [vmware] Active machines: %d" % (machine_count) )
  
 
 
  return pool_index 


def _revert(vm):
    global ESX_SERVER
    global ESX_USERNAME
    global ESX_PASSWORD
    _load_config()

    server = VIServer()
    server.connect(ESX_SERVER, ESX_USERNAME, ESX_PASSWORD)
    vm_handle = server.get_vm_by_name(vm['name'])

    print "[*] [%s] Reverting to snapshot %s:" % (vm['name'],vm['snapshot_name'])
    logging.info("[*] [%s] Reverting to snapshot %s:" % (vm['name'],vm['snapshot_name']))

    vm_handle = server.get_vm_by_name(vm['name'])
    vm_handle.revert_to_named_snapshot(vm['snapshot_name'])

    if vm_handle.get_current_snapshot_name() != vm['snapshot_name']:
        print "[!] [%s] Error when Reverting VM: %s" % (vm['name'],output)
        logging.info("[!] [%s] Error when starting VM: %s" % (vm['name'],output))
        return False
    
    return True

def _start(vm):
    global ESX_SERVER
    global ESX_USERNAME
    global ESX_PASSWORD
    _load_config()

    server = VIServer()
    server.connect(ESX_SERVER, ESX_USERNAME, ESX_PASSWORD)
    vm_handle = server.get_vm_by_name(vm['name'])

    print "[*] [%s] Starting VM" % (vm['name'])    
    logging.info("[*] [%s] Starting VM" % (vm['name']))

    if vm_handle.is_powered_on():
      print '[*] Machine %s is already powered on' % (vm['name'])
      return True
    else:
      print '[*] powering on machine %s:' % (vm['name'])
      vm_handle.power_on()
    
    if vm_handle.is_powered_on():
      print '[*] Machine is on now: %s' % (vm['name'])
      return True

def _suspend(vm):
    global ESX_SERVER
    global ESX_USERNAME
    global ESX_PASSWORD
    _load_config()

    server = VIServer()
    server.connect(ESX_SERVER, ESX_USERNAME, ESX_PASSWORD)
    vm_handle = server.get_vm_by_name(vm['name'])


    print " [*] [%s] Suspending VM" % (vm['name'])
    logging.info(" [*] [%s] Suspending VM" % (vm['name']))
    vm_handle.suspend()
    

    if vm_handle.is_suspended():
      print '[*] Machine is now suspended: %s' % (vm['name'])
      logging.info(" [*] [%s] Machine is now suspended " % (vm['name']))
      return True
    else:
      print '[!] Could not suspend VM: %s' % (vm['name'])
      logging.info(" [!] [%s] Could not suspend VM" % (vm['name']))
      return False


def _get_mem_path(vm):    
	command = '/bin/ls -tr ' + vm['vmdk_path'] + '*.vmss | tail -1'
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
     