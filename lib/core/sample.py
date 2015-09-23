#! /usr/bin/python
import socket
import hashlib
import yaml
import os
import random
import string
import shutil

VolatilityBot_Home = ""



def _load_config():
  global VolatilityBot_Home
  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	VolatilityBot_Home = dataMap['mainconfig']['general']['VolatilityBot_Home']
         
	return True       
 
  return False
  
def send_file(filename,target_vm_ip):
    try:    
        file = open(filename, "rb")
        sock = socket.socket()
        sock.connect((target_vm_ip, 9999))
        while True:
            chunk = file.read(65536)
            if not chunk:
                break  # EOF
            sock.sendall(chunk)	
        return True
    except:
        return False
        

def calc_SHA256(filename):
    return hashlib.sha256(open(filename).read()).hexdigest()     
    
def calc_MD5(filename):
    return  hashlib.md5(open(filename).read()).hexdigest()

def _copy_sample_to_store(originalfilename):
	_load_config()
	sha256 = hashlib.sha256(open(originalfilename).read()).hexdigest()
	directory =   VolatilityBot_Home + '/Store/' + sha256    

	if not os.path.exists(directory):
	    os.makedirs(directory)             	    
	    shutil.copyfile(originalfilename, VolatilityBot_Home + '/Store/' + sha256 + '/' + sha256 + '.bin') 	

    
def _new_workdir(filename):
	_load_config()
	sha256 = hashlib.sha256(open(filename).read()).hexdigest()
	directory =   VolatilityBot_Home + '/Store/' + sha256
	#Generate a random string, in order to not overwrite file in future dumps:
	random_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))
	run_workdir =  directory + '/' + random_string
	
	if not os.path.exists(directory):
	    os.makedirs(run_workdir)             	    
	    shutil.copyfile(filename, VolatilityBot_Home + '/Store/' + sha256 + '/' + sha256 + '.bin') 	    
	    os.makedirs(run_workdir + '/injected/')
	else:
	    os.makedirs(run_workdir + '/injected/')	    
                	    	    

	print "Sample SHA256: %s" % (sha256)

	return(run_workdir)