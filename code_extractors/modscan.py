# -*- coding: utf-8 -*-
"""
Created on Tue Feb 10 08:34:30 2015

@author: Martin
"""

from lib.core import sample
from lib.core import DataBase
import subprocess
import yaml
import os
import re
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

	VolatilityBot_Home = dataMap['mainconfig']['general']['VolatilityBot_Home']
	volatility_path  = pipes.quote(dataMap['mainconfig']['general']['volatility_path'])

	return True       
 
  return False

def _run(vm_name,f_profile,vmem_path,workdir,sample_id):
    global VolatilityBot_Home
    global volatility_path
    _load_config()
    
    mod_white_list = ['TDTCP.SYS','RDPWD.SYS','kmixer.sys','Bthidbus.sys','rdpdr.sys','tdtcp.sys','tssecsrv.sys']
    

    
    
    #Get golden image data
    modscan_gi = []
    f = open(VolatilityBot_Home + '/GoldenImage/' + vm_name + '/modscan', 'r')
    modscan_GoldenImage = f.readlines()
    for line in modscan_GoldenImage:
    	splitted_line = re.split('\s+',  line.rstrip('\n'))  
    	if splitted_line[0].startswith("0x"):  
    		try:  
	    		entry = dict()
	    		entry['offset'] = splitted_line[0]
	    		entry['name'] = splitted_line[1]
	    		entry['base'] = splitted_line[2]
	    		entry['size'] = splitted_line[3]
	    		entry['filename'] = splitted_line[4]
	    		modscan_gi.append(entry)
	    		#print entry    
	        except:
	    		#print "Skipping a non-parseable line:" + line
	    		pass
    f.close()
    #print modscan_gi
    
    #Get new modscan:
    command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' modscan'
    proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
    modscan_run = []
    for line in iter(proc.stdout.readline, ''):	
        splitted_line = re.split('\s+',  line.rstrip('\n'))  
        if splitted_line[0].startswith("0x"):  
            try:  
                entry = dict()
                entry['offset'] = splitted_line[0]
                entry['name'] = splitted_line[1]
                entry['base'] = splitted_line[2]
                entry['size'] = splitted_line[3]
                entry['filename'] = splitted_line[4]
                modscan_run.append(entry)
				#print entry    
            except:
                pass
	#print modscan_run    
    
    new_modules = []
    for mod in modscan_run:
        new_mod = True
        for mod_gi in modscan_gi:
            if (mod['filename'] == mod_gi['filename']):
                if (mod['size'] == mod_gi['size']):
                    new_mod = False
                    
        for wl_mod in mod_white_list:
            #print '[DEBUG] modscan %s : %s' % (mod['filename'],wl_mod)
            if (mod['name'] == wl_mod):
                new_mod = False
            
            

        if (new_mod):            
            print "Identified a new module: %s - %s" % (mod['filename'],mod['size'])
            new_modules.append(mod)
            


            command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' moddump -b ' + mod['base'] + ' -x -D ' + workdir + '/'
            proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
            output = proc.stdout.read()
	
            try:
                #Name should be:  0xf855a000 pci.sys     OK: driver.f855a000.sys
                base = mod['base']
                src = workdir + "/driver." + base[2:] + ".sys"
  
		
  
                dest = workdir + "/" + mod['name'] + "." + mod['base'] + "._sys"
		
                os.rename(src,dest)
  
                file_sha256 = sample.calc_SHA256(dest)     
                file_md5 = sample.calc_MD5(dest)    
                file_ephash = ephash.calc_ephash(dest)
                

                DataBase.add_dump(sample_id,file_md5,file_sha256,file_ephash,'n/a',mod['name'],"kmd_" + f_profile,dest)  
                
                #Adding tag to sample: (loads_kmd)
                DataBase.add_tag("loads_KMD",sample_id)
            
              
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
  
            except:
                print "Dump of " + mod['name'] + "failed."
    
    
    
    return True
