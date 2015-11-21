#! /usr/bin/python
from lib.common import pslist
from lib.core import sample
from lib.core import DataBase
import subprocess
import os
import re
import pefile
from post_processing import strings
from post_processing import yara_postprocessor
from post_processing import SemanticAnalyzer2
from post_processing import static_report
from post_processing import ephash
import yaml
import pipes

volatility_path = ''

def load_config():
    global volatility_path
    #volatility_path
    config_file_path = './conf/main.conf'

    if os.path.isfile(config_file_path):
        f = open(config_file_path)
        # use safe_load instead load
        dataMap = yaml.safe_load(f)
        f.close()
        #print dataMap
  
        volatility_path  = pipes.quote(dataMap['mainconfig']['general']['volatility_path'])
    

def _run(vm_name,f_profile,vmem_path,workdir,sample_id):
	
 	global volatility_path    
	#Load config
	load_config()        
    
	#Load the pslist golden image from disk
	#pslist_gi = pslist.load_golden_image(vm_name)
	pslist_new = pslist.get_new_pslist(vmem_path,f_profile)     
	command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' malfind -D ' + workdir + '/injected' + '/'
	print command   
	proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
	output = proc.stdout.read()
	#print output

	#Find malfind injections that are binaries, and rename them
	for root, directories, files in os.walk(workdir + '/injected'):
	    for filename in files:
	        #print "Processing %s root:(%s) dir(%s)" % (filename,root,directories)
	        splitted_line = re.split('\.',  filename.rstrip('\n'))
	        #print 'offset: %s, Imagebase: %s' % (splitted_line[1],splitted_line[2])
	        offset = splitted_line[1]
	        imagebase = splitted_line[2]
	                
	        try:
	            pe =  pefile.PE(workdir + '/injected/' + filename)
	            isPE = True
	        except:
	            isPE = False
	            
	        if (isPE):
	            #Adding tag to sample: (loads_kmd)
	            DataBase.add_tag("Injects_Code",sample_id)
            
	            print "[*] Processing " + workdir + '/injected/' + filename
	            print 'offset: %s, Imagebase: %s' % (splitted_line[1],splitted_line[2])
	            print "Altering image base: %s => %s" % (pe.OPTIONAL_HEADER.ImageBase,imagebase)
	            pe.OPTIONAL_HEADER.ImageBase = int(imagebase, 16)
	            
	            for section in pe.sections:
	                #copy raw_adress to virtual address
	                print "==" + section.Name + "=="
	                print "Modifying virtual addresses:"
	                print "%s => %s" % (hex(section.VirtualAddress),hex(section.PointerToRawData))
	                
	                section.VirtualAddress = section.PointerToRawData
	            
             
             
	            #Get original process name
	            procname = "unknown"
	            
	            #print '[DEBUG GI]'
	            #print 'golden image data: %s' % pslist_new
             
	            for proc_gi in pslist_new:
	                #print '[DEBUG] Look for process: gi - "%s" == new - "%s"' % (proc_gi['offset'],offset)                     
	                if (str(proc_gi['offset']) == offset):
	                    print "Found process name: %s" % (proc_gi['name'])
	                    procname = proc_gi['name']
	                    pid = str(proc_gi['pid'])

	            
	            outputpath = workdir + '/injected/' + procname + '.' + offset +  '.' + imagebase +  '.fixed_bin'
	            pe.write(filename=outputpath)
	            os.remove(workdir + '/injected/' + filename)
             
	            if procname != 'unknown':
                     #Generate impscan IDC
                     command = volatility_path + ' --profile ' + f_profile + ' -f '  + vmem_path + ' impscan -b ' + imagebase + ' -p ' + pid + ' --output=idc'
                     print command
                     proc = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE)
                     output = proc.stdout.read()
                     print '[*] impscan IDC output'
                     print output
                     
                     #Write IDC data to file
                     obj = open(outputpath + '.idc', 'wb')
                     obj.write('#include <idc.idc>\n')
                     obj.write('static main(void) {{\n')
                     obj.write(output)                
                     obj.write('Exit(0);}}')
                     obj.close                     
                 
	            #Add dump to db
	            file_sha256 = sample.calc_SHA256(outputpath)     
	            file_md5 = sample.calc_MD5(outputpath)    
             
	            #Calc imphash, or make the parameter = fail
	            f_ephash = ephash.calc_ephash(outputpath)
	            #Calc EPhash, or make the parameter = fail       
	            f_imphash = ephash.calc_imphash(outputpath)
             

	            DataBase.add_dump(sample_id,file_md5,file_sha256,f_ephash,f_imphash,procname,"injected_" + f_profile,outputpath)    
             
	            #Load post processing modules here, if needed
	            strings_json = strings._run(outputpath,sample_id)
	            #Write output to file:
	            obj = open(outputpath + '.strings', 'wb')
	            obj.write(strings_json)
	            obj.close
             
	            #yara output:
	            yara_output = yara_postprocessor._run(outputpath,sample_id)
	            if (yara_output != "none"):                 
                     obj = open(outputpath + '.yara_results', 'wb')
                     obj.write(yara_output)
                     obj.close
        
	            #Static analysis
	            static_report_data = static_report._run(outputpath,sample_id)
	            if (static_report_data != "none"):
                     obj = open(outputpath + '.static_report', 'wb')
                     obj.write(static_report_data)
                     obj.close        
                     
	            YSA_output = SemanticAnalyzer2._run(outputpath,sample_id)
	            if (YSA_output != "none"):
                     obj = open(outputpath + '.ysa_results', 'wb')
                     obj.write(YSA_output)
                     obj.close                
                                 
                 
	           
             
             
             
	        else:
	            if ((filename != "fixed") & (root[-5:] != "fixed")):
                     #print "Not PE! Deleting"
                     os.remove(workdir + '/injected/' + filename)


