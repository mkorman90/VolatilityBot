#! /usr/bin/python
import os
import yaml
import pipes
import subprocess
import random
import string
import time


vmindex = []
vmrun_path = ""
gui = ""



def _load_config():
  global vboxrun_path
  global gui    
  if os.path.isfile('conf/virtualbox.conf'):
	f = open('conf/virtualbox.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

  vboxrun_path_tmp = dataMap['general']['vboxmanage_path']
  vboxrun_path = vboxrun_path_tmp.replace(' ','\\ ')
  if (dataMap['general']['gui']):
    gui = "gui"     
	
  return True       
 
  
def _init():
  machine_count = 0
  global vboxrun_path
  global gui
  
  print "[*] Loading virtualbox module"    
  if os.path.isfile('conf/virtualbox.conf'):
	f = open('conf/virtualbox.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

  vboxrun_path_tmp = dataMap['general']['vboxmanage_path']
  vboxrun_path = vboxrun_path_tmp.replace(' ','\\ ')
  gui = dataMap['general']['gui']
 
  #print dataMap['machines']
  for vm_cfg in dataMap['machines']:
         vm = {}
         vm['enabled']            = dataMap['machines'][vm_cfg]['enabled']
         vm['name'] 			     = dataMap['machines'][vm_cfg]['name']
         vm['IP'] 				 = dataMap['machines'][vm_cfg]['IP']
         vm['snapshot_name'] 	 = dataMap['machines'][vm_cfg]['snapshot_name']
         vm['status'] 			 = dataMap['machines'][vm_cfg]['status']
         if (vm['enabled']):
             machine_count  = machine_count + 1

         vmindex.append(vm)
					
         print " - Loaded machine - %s" % (vm['name'])
			
  print "Active machines: %d" % (machine_count) 
 
 
  return vmindex 


def _revert(vm):
    _load_config()
    print " [*] Reverting %s to snapshot %s:" % (vm['name'],vm['snapshot_name'])
    #vboxmanage snapshot wxp_01 restore VolatilityBot
    command = vboxrun_path + ' controlvm  ' + vm['name'] + ' poweroff'
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    
    command = vboxrun_path + " snapshot " + vm['name'] + " restore " + vm['snapshot_name']
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    print output
    
    return True

def _start(vm):
    _load_config()
    print " [*] Starting vm, %s:" % (vm['name'])    
    command = vboxrun_path + " startvm " +  vm['name']
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    print output
    
    return True

def _suspend(vm):
    _load_config()
    print " [*] Suspending vm: %s " % (vm['name'])
    command = vboxrun_path + " controlvm " +  vm['name'] + " pause"
    print command
    p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, error = p.communicate()
    print output

    
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
	_load_config()
     #Check if dump for this sample exists (by vmname - If it exsits: return name, if not: create and return dump name)
	dump_name = 'vboxdump_' +  vm['name']
	if os.path.isfile('/tmp/' + dump_name):
          return '/tmp/' + dump_name
	else:                  
          command = vboxrun_path + ' debugvm ' + vm['name'] + ' dumpguestcore --filename /tmp/' + dump_name
          proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
          print "Got dump name:" + dump_name
          time.sleep(10)
          return '/tmp/' + dump_name    
    

def _cleanup(vm):
	os.remove('/tmp/vboxdump_' + vm['name']) 
	print "[*] Cleanup after %s done." % (vm['name'])   
	return True     

    
     