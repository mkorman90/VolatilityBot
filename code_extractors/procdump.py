#! /usr/bin/python

from lib.common import pslist
from lib.core import sample
from lib.core import DataBase
import subprocess
import os
import yaml
import pipes

from post_processing import strings
from post_processing import yara_postprocessor
from post_processing import static_report
from post_processing import ephash



VolatilityBot_Home = ""
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
	global volatility_path
	_load_config()

	golden_image = pslist.load_golden_image(vm_name)
	new_pslist = pslist.get_new_pslist(vmem_path,f_profile)

	new_processes = []
	for proc in new_pslist:
	    new_proc = True
	    for proc_gi in golden_image:
	        if (proc['pid'] == proc_gi['pid']):
	            new_proc = False
             
             #TODO! Local patch!! Remove on production!!
	        if (proc['name'] == 'wmiprvse.exe'):
	            new_proc = False
             
	    if (new_proc):
	        print "Identified a new process: %s - %s" % (proc['pid'],proc['name'])
	        new_processes.append(proc)
	
	for procdata in new_processes:
		command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' procdump -p ' + str(procdata['pid']) + ' -D ' + workdir + '/'
		proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
		output = proc.stdout.read()
		#print output
		try:
			src = workdir + "/executable." + str(procdata['pid']) + ".exe"
	  
			
	  
			dest = workdir + "/" + procdata['name'] + "." + str(procdata['pid']) + "._exe"
			#print " Renaming %s to %s" % (src,dest)
			os.rename(src,dest)

			file_sha256 = sample.calc_SHA256(dest)     
			file_md5 = sample.calc_MD5(dest)   
			file_ephash = ephash.calc_ephash(dest)     
			file_imphash = ephash.calc_imphash(dest)
             
			DataBase.add_dump(sample_id,file_md5,file_sha256,file_ephash,file_imphash,procdata['name'],"new_process_" + f_profile,dest)    
                
			strings_json = strings._run(dest,sample_id)
			#Write output to file:
			obj = open(dest + '.strings', 'wb')
			obj.write(strings_json)
			obj.close
             
			#yara output:
			yara_output = yara_postprocessor._run(dest,sample_id)
			if (yara_output != "none"):                 
			 obj = open(dest + '.yara_results', 'wb')
			 obj.write(yara_output)
			 obj.close
                     
			static_report_data = static_report._run(dest,sample_id)
			if (static_report_data != "none"):
			 obj = open(dest + '.static_report', 'wb')
			 obj.write(static_report_data)
			 obj.close    
                     

	  
			return True
		except:
			print "Dump of " + str(procdata['pid']) + "failed."
			print output
			return False
