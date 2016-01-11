#! /usr/bin/python
import os
import yaml
import pipes
import subprocess
import logging
import sys

vmindex = []
vmrun_path = ""
gui = ""
    


def _load_config():
	''' Load config files and fill globals '''
	global xl_path
	global xbox_working_path
	global gui
	global dataMap
	if os.path.isfile('conf/xen_vmifs.conf'):
		f = open('conf/xen_vmifs.conf')
		# use safe_load instead load
		dataMap = yaml.safe_load(f)
		f.close()
	xbox_name = dataMap['general']['xl_path']
	xl_path = xbox_name.replace(' ','\\ ')
	xbox_name = dataMap['general']['xbox_working_path']
	xbox_working_path = xbox_name.replace(' ','\\ ')
	gui = False
	if (dataMap['general']['gui']):
		gui = dataMap['general']['gui']
	return True  


def _init():
	''' Loading machines pools config files '''
	print "[*] Loading XEN module"    
	_load_config()
	machine_count = 0
	pool_index = {} 
	for res_pool in dataMap['general']['machine_resource_pools']:
		if dataMap['general']['machine_resource_pools'][res_pool]['active']:
			print '[*] Loading Machine Resouce Pool: %s' % res_pool
			pool_index[res_pool] = []
			for vm_cfg in dataMap['general']['machine_resource_pools'][res_pool]['machines']:
				vm = {}
				vm['enabled']       = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['enabled']
				vm['name'] 			   = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['name']
				vm['IP'] 				   = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['IP']
				vm['snapshot_name'] = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['snapshot_name']
				vm['status'] 			 = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['status']
				vm['config_file']       = dataMap['general']['machine_resource_pools'][res_pool]['machines'][vm_cfg]['config_file']
				vm['profile']    = dataMap['general']['machine_resource_pools'][res_pool]['profile']
				if (vm['enabled']):
					machine_count  = machine_count + 1
    
				pool_index[res_pool].append(vm)
		
				print " - Loaded machine - %s" % (vm['name'])
				logging.info(" - Loaded machine - %s" % (vm['name']))   
		else:
			print '[!] Inactive Machine Resouce Pool: %s' % res_pool     
	print "[*] [xen] Active machines: %d" % (machine_count) 
	logging.info("[*] [xen] Active machines: %d" % (machine_count) )
	return pool_index 

def _cleanup(vm,d=True):
	''' Remove monted memory and kill vm by default '''
	_load_config()
	dump_name = xbox_working_path + 'xboxmem_' +  vm['name']
	print "[*] [xen]  Cleanup %s forlder and/or exiting domain" % (vm['name'])
	if os.path.exists(dump_name):
		print "[*] [xen]  Removing %s" % dump_name
		command = "rm  " + dump_name 
		if os.path.isdir(dump_name):
			print "[*] [xen]  Trying to unmount %s" % dump_name
			command = "/bin/umount " + dump_name
			print " >  %s" % command
			p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			output, error = p.communicate()
			print output
			command = "rm -Rf " + dump_name
		print " >  %s" % command
		p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		output, error = p.communicate()
		print output
	if d:
		destroy_xbox(vm)
	return True

def destroy_xbox(vm):
	''' Kill DomU '''
	_load_config()
	print "[*] [xen]  Destroying %s if still up." % (vm['name'])
	command = xl_path + ' destroy ' + vm['name']
	print " >  %s" % command
	p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, error = p.communicate()
	print output


def _revert(vm):
	''' should be reverting snapshot but it is done on start-up in xen '''
	print "[*] [xen]  Reverting %s is futile." % (vm['name'])
	"""	
	_load_config()
	destroy_xbox(vm)
	print "[*] [xen]  Reverting %s to snapshot %s:" % (vm['name'],vm['snapshot_name'])
	#vboxmanage snapshot wxp_01 restore VolatilityBot
	command = "%s restore %s%s %s%s" % (xl_path,xbox_working_path,vm['config_file'],xbox_working_path,vm['snapshot_name'])
	print " >  %s" % command
	p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, error = p.communicate()
	print output
	if gui:
		subprocess.Popen(gui,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	return True
	"""
	return True

def _start(vm):
	''' Load the DomU by restoration, destroy any previous and load gui command if provided '''
	_load_config()
	_cleanup(vm)
	print "[*] [xen]  Starting and restoring %s" % (vm['name'])
	command = "%s restore %s%s %s%s" % (xl_path,xbox_working_path,vm['config_file'],xbox_working_path,vm['snapshot_name'])
	print " >  %s" % command
	p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, error = p.communicate()
	print output
	if gui:
		subprocess.Popen(gui,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	return True

def _suspend(vm):
	''' suspend the vm '''
    _load_config()
    print "[*] [xen]  Suspending %s " % (vm['name'])
    command = xl_path + " pause " +  vm['name']
    print " >  %s" % command
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    print output
    return True

def _get_mem_path(vm):
	''' mount vm memory and provide path to it '''
	_load_config()
	_cleanup(vm,False)
     #Check if dump for this sample exists (by vmname - If it exsits: return name, if not: create and return dump name)
	dump_name = xbox_working_path + 'xboxmem_' +  vm['name']
	print "[*] [xen]  Getting mempath (%s) for %s" % (dump_name,vm['name'])
	command = "/usr/local/bin/vmifs name " + vm['name'] + " " + dump_name
	print " >  %s" % command
	p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, error = p.communicate()
	print output
	return dump_name + "/mem" 
    

     


