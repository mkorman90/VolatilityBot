#! /usr/bin/python

#REMOVE LATER!
import sys
sys.path.append("/home/martin/MWA/VolatilityBot/volatilitybot")

import json

from lib.core import sample
from lib.core import DataBase
import subprocess
import os
import yaml
import pipes
import re
import pydasm
import binascii

from post_processing import strings
from post_processing import yara_postprocessor
from post_processing import static_report



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
        
	command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' apihooks'
	proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
	#output = proc.stdout.readlines()
 

     	
      
	hook_data = []
 
	#with open('/home/martin/MWA/apihooks.txt') as f:
     #    output = f.readlines()
    
 
	disasm_code_started = False
	whitelisted_patch = False
	in_patch_disassembly = False
	hook_code = ""
	export = ""
	module = ""
	process = ""
	hook_mode = ""
	hook_type = ""
 	hooking_module = ""
	count = 0
	hooks_count = 0     
	
	#Define whitelist         
	whitelist = ["IEFRAME.dll","adsldpc.dll","glib-2.0.dll","MSVCR120.dll","RPCRT4.dll"]

	original_apihooks = open(workdir + '/original.apihooks', 'wb')
	
 
	for line in iter(proc.stdout.readline,''):
         #print line     
         original_apihooks.write(line) 
         mode_matches = False
         p = re.compile('Hook mode: (.+)')
         t =  p.match(line)
         if t:
             hook_mode =  t.group(1)    
             #print 'Hook mode: ' + hook_mode   
            #Usermode or Kernelmode
         
         #Get hook type
         p = re.compile('Hook type: (.+)')
         t =  p.match(line)
         if t:
             hook_type =  t.group(1)    
             #print 'Hook Type: ' + hook_type
            #NT Syscall or Inline/Trampoline or Import Address Table (IAT)
             
             
        #Get proccess name    
         if hook_mode == "Usermode":
             p = re.compile('Process: \d+ \((.+)\)')
             t =  p.match(line)
             if t:
                 process =  t.group(1)
                 #print 'process_name:' + process

             
         #Find the hook function, and hooked module 
         if hook_mode == "Usermode":
             if (hook_type == "NT Syscall"):
                p = re.compile('Function: (.+)')   
                t = p.match(line)
                if t:
                    module = t.group(1)
                    export = t.group(1)
                    hook_code = ""
                    count = 0
             else:    
                 p = re.compile('Function: ([\w_\d]+\.(dll|DLL))!([\w_\d]+)')   
                 t = p.match(line)
                 if t:
                     module = t.group(1)
                     export = t.group(3)
                     hook_code = ""
                     count = 0
                     #print line
                     #print "%s->%s" % (module,export)
         else:
            #Function: kernel32.dll!CreateProcessA at 0x7c80236b
            p = re.compile('Function: (.+)!(.+) at 0x[a-f0-9]{8}')   
            t = p.match(line) 
            if t:
                module = t.group(1)   
                export = t.group(2)
                hook_code = ""
                count = 0
                #print "kmd: %s" % (export)
               
         
         #Check for whitelist
      
         p = re.compile('Hooking module: (.+)')         
         t = p.match(line)
         if t:
             hooking_module = t.group(1)
             if any(hooking_module in s for s in whitelist):
                 #print "%s is whitelisted" % hooking_module
                 whitelisted_patch = True
             else:
                 #print "%s is NOT whitelisted" % hooking_module
                 whitelisted_patch = False                   
 
         #Check if we reached disassembly of the patch:
         p = re.compile('Disassembly\(0\):')
         t = p.match(line)
         if t:
             in_patch_disassembly = True
             #print "Now in dissassembly!"
             
         #
         if (in_patch_disassembly):
             #print line
             p = re.compile('Disassembly\(1\):')
             t = p.match(line)
             if t:
                 disasm_code_started = True
                 #print "disasm started"
             elif (disasm_code_started):
                 #print "Hookmodule: %s In patch disassebly: %s!%s - %s" % (hooking_module,module,export,line)
                 #print "D: " + line
               
                 arr = line.split()     
                 if ((not line.isspace()) & (not line.startswith("*")) & (count < 12)):
                     try:
                         hook_code+=arr[1]
                         count = count + 1         
                     except:
                         print '[*] Skipping corruped hook line'
 
         #If this is the end of the hook, process it:       
         p = re.compile('^[\*]{72}')         
         t = p.match(line) 
         if t:
             disasm_code_started = False
             in_patch_disassembly = False  
             
             entry = {}
             
             if (process != ''):
                 entry['process_name'] = process
             else:
                 entry['process_name'] = 'unknown'  
                 
             entry['module'] = module
             entry['export'] = export
             entry['hook_code'] = hook_code
             entry['hook disassembly'] = ''
             entry['hooking_module'] = hooking_module

             offset = 0
             outDis = []
             
             hex_data = hook_code.decode("hex")             
             
             while offset < len(hex_data):
                 i = pydasm.get_instruction(hex_data[offset:],pydasm.MODE_32)
                 tmp = pydasm.get_instruction_string(i,pydasm.FORMAT_INTEL,offset)
                 outDis.append(tmp)
                 if not i:
                     return outDis
                 offset +=  i.length
             entry['hook disassembly'] = outDis    
             
             if (hooking_module == '<unknown>'):
                 hooks_count = hooks_count + 1
                 hook_data.append(entry)
             
             hooking_module = ''
             hook_code = ''
             module = ''
             export = ''
             
             
	print json.dumps(hook_data, indent=4, sort_keys=True)
 
	original_apihooks.close
    
	if (hooks_count > 0):
 
        	hooks_json = json.dumps(hook_data, indent=4, sort_keys=True)
        	obj = open(workdir + '/code.hooks', 'wb')
        	obj.write(hooks_json)
        	obj.close
    		
  
        	file_sha256 = sample.calc_SHA256(workdir + '/code.hooks')     
        	file_md5 = sample.calc_MD5(workdir + '/code.hooks')    

        	DataBase.add_dump(sample_id,file_md5,file_sha256,'n/a','n/a','Code Hooks',"Hooks_" + f_profile,workdir + '/code.hooks')
    
    
        	#Adding tag to sample: (loads_kmd)
        	DataBase.add_tag("Hooks_APIs",sample_id)

  
    
    

        

	return True

