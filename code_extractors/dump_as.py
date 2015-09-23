#! /usr/bin/python

from lib.common import pslist
from lib.core import sample
from lib.core import DataBase
import subprocess
import os
import yaml
import pipes

volatility_path = ""

def _load_config():
  global VolatilityBot_Home
  global volatility_path
  
  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	volatility_path  = pipes.quote(dataMap['mainconfig']['general']['volatility_path'])

	return True       
 
  return False
  
def _run(vm_name,f_profile,vmem_path,workdir,sample_id):
    
	#Load config
 	global volatility_path
	_load_config()   
    
	golden_image = pslist.load_golden_image(vm_name)
	new_pslist = pslist.get_new_pslist(vmem_path)
 
 	new_processes = []
	for proc in new_pslist:
	    new_proc = True
	    for proc_gi in golden_image:
	        if (proc['pid'] == proc_gi['pid']):
	            new_proc = False
	    if (new_proc):
	        print "Identified a new process: %s - %s" % (proc['pid'],proc['name'])
	        new_processes.append(proc)

	for procdata in new_processes:
		command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' memdump -p ' + procdata['pid'] + ' -D ' + workdir + '/'
		proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
		output = proc.stdout.read()
		#print output
		try:
			src = workdir + "/" + procdata['pid'] + ".dmp"
	  
			
	  
			dest = workdir + "/" + procdata['name'] + "." + procdata['pid'] + "._dmp"
			#print " Renaming %s to %s" % (src,dest)
			os.rename(src,dest)

			file_sha256 = sample.calc_SHA256(dest)     
			file_md5 = sample.calc_MD5(dest)     

			DataBase.add_dump(sample_id,file_md5,file_sha256,procdata['name'],"procdump_" + f_profile,dest)  
                    

                 #Post processing goes here:
                 #Modules ideas: URL and I.P extracting                
	  
			return True
		except:
			print "Dump of " + procdata['pid'] + "failed."
			print output
			return False