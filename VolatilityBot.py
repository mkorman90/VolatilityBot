#! /usr/bin/python
import os
import yaml
import pipes
import threading
import importlib
import time
from lib.core import sample
from lib.core import DataBase
from lib.core import CodeExtractor
from post_processing import ephash
import pefile
import argparse
from time import gmtime, strftime
from datetime import datetime
from threading import Thread
import threading
import logging
import json


#vmindex is a list containing all managed machines
active_pools = []
vmindex = []
global lock_vmindex 
lock_vmindex = {}

global machine_status_vmindex 
machine_status_vmindex = {}

#Counters for statistics
global machine_statistics
machine_statistics = {}
global sample_analysis_time
sample_analysis_time = []

#Machine failure threshold counters
global machine_failure_threshold
machine_failure_threshold = 3

#A lock for machine communication, so not more than one machine communicates with a VM at a time
global vm_comm_lock
vm_comm_lock = threading.Lock()

vmrun_path = ""
VolatilityBot_Home = ""
machine_type = ""
log_path = ""
conf_path = ""

modules_list = []

#Load configuration file
def read_config():
	global vmindex
	global log_path 
	global lock_vmindex
	global vmrun_path
	global VolatilityBot_Home
	global machine_type
	global conf_path
	global machine_failure_threshold
	global active_pools

	config_file_path = ''
	if conf_path == '':
         config_file_path = './conf/main.conf'
	else:
         print '[*] Loading configuration from %s' % (config_file_path)     
         config_file_path = conf_path

	if os.path.isfile(config_file_path):
		f = open(config_file_path)
		# use safe_load instead load
		dataMap = yaml.safe_load(f)
		f.close()
  
		VolatilityBot_Home  = pipes.quote(dataMap['mainconfig']['general']['VolatilityBot_Home'])
		machine_type = dataMap['mainconfig']['general']['machine_type']	  
		log_path  = pipes.quote(dataMap['mainconfig']['general']['log_path'])
		machine_failure_threshold  = dataMap['mainconfig']['general']['machine_failure_threshold']
		active_pools = dataMap['mainconfig']['general']['active_pools'].split(',')
      
  
  
		return True
	else:
		print "[*] %s is not a file, or not found." % (config_file_path)
		return False


#Execute a sample on a VM chosen from the list
def run_process_on_vm(f_vm,f_sleeptime,f_fname,f_sample_id):
    global lock_vmindex
    global init_machine
    global revert
    global start
    global suspend
    global get_mem_path
    global modules_list
    global cleanup
    
    global machine_status_vmindex
    global machine_statistics
    global sample_analysis_time


    start_time = time.time()
    
    #Change analysis status to started
    DataBase.change_analysis_status(f_sample_id,'pre-processing')
    
    logging.basicConfig(filename=log_path + '/VolatilityBot.log', level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
    logging.info('[*] [%s] Now working on sample %s.' % (f_vm['name'],f_sample_id))
    
    
    workdir = sample._new_workdir(f_fname)
    
    Machine_Is_OK = True
    
    if not revert(f_vm):
        Machine_Is_OK = False

        
    if not start(f_vm):
        Machine_Is_OK = False
            
    #If revert or start failed, skip this analysis, increase machine fail counter            
    if not Machine_Is_OK:
        #Not releasing the lock on this machine on purpose!! It should not be used!
        DataBase.change_analysis_status(f_sample_id,'failed')
        logging.error('[!] [%s] FATAL: Machine could not be reverted.' % (f_vm['name']))
        print '[!] [%s] FATAL:Machine could not be reverted.' % (f_vm['name'])

        machine_status_vmindex[f_vm['name']] = machine_status_vmindex[f_vm['name']] + 1
        logging.error("[!] Increased the fail counter of the following machine: %s to %d" % (f_vm['name'],machine_status_vmindex[f_vm['name']]))

        #If machine failed more than 3 times, mark as failed for the rest of the analysis queue
        if  machine_status_vmindex[f_vm['name']] >= 3:
              logging.error('[!] [%s] Marked as fail for the rest of the analysis queue. Not releasing machine lock.' % (f_vm['name']))
        else:
            lock_vmindex[f_vm['name']].release() 

        machine_statistics[f_vm['name']]['samples_failed'] = machine_statistics[f_vm['name']]['samples_failed'] + 1

        cleanup(f_vm)
        
        return False
            
            
    #Sleep before sending the sample to the machine            
    print "[*] [%s] Sleeping 10 seconds..." % (f_vm['name'])
    logging.info("[*] [%s] Sleeping 10 seconds..." % (f_vm['name']))
    time.sleep(10)

    #Send the sample to the VM
    print "[*] [%s] Sending executable %s to vm: %s I.P: %s" % (f_vm['name'],f_fname,f_vm['name'],f_vm['IP']) 
    logging.info("[*] [%s] Sending executable %s to vm: %s I.P: %s" % (f_vm['name'],f_fname,f_vm['name'],f_vm['IP']) )    
    
    if sample.send_file(f_fname,f_vm['IP']):
        DataBase.change_analysis_status(f_sample_id,'Processing on machine: %s' % f_vm['profile'])
        #Sleep the defined ammount of time in order for the malware to execute            
        print "[*] [%s] Sleeping %s seconds..." % (f_vm['name'],str(f_sleeptime))
        logging.info("[*] [%s] Sleeping %s seconds..." % (f_vm['name'],str(f_sleeptime)))
        time.sleep(int(f_sleeptime))
        
        #Verify that VM suspend succeded, else, increase fail counter
        if not suspend(f_vm):
            #Not releasing the lock on this machine on purpose!! It should not be used!
            DataBase.change_analysis_status(f_sample_id,'failed')
            logging.error('[!] FATAL: %s machine could not be suspended. Marked as failed for the rest of the analysis queue' % (f_vm['name']))
            print '[!] FATAL: %s machine could not be suspended. Marked as failed for the rest of the analysis queue' % (f_vm['name'])

            machine_status_vmindex[f_vm['name']] = machine_status_vmindex[f_vm['name']] + 1
            logging.error("[!] Increased the fail counter of the following machine: %s to %d" % (f_vm['name'],machine_status_vmindex[f_vm['name']]))  

            #If machine failed more than 3 times, mark as failed for the rest of the analysis queue        
            if  machine_status_vmindex[f_vm['name']] >= 3:
                  logging.error('[!] [%s] Marked as fail for the rest of the analysis queue. Not releasing machine lock.' % (f_vm['name']))
            else:
                lock_vmindex[f_vm['name']].release() 
                
          
            machine_statistics[f_vm['name']]['samples_failed'] = machine_statistics[f_vm['name']]['samples_failed'] + 1
            
            cleanup(f_vm)
            
            return False
         
        #Execute all configured modules on that Machine
        
        #Get memory path:         
        vmem_path =  get_mem_path(f_vm)

        #Execute all configure modules:        
        for mod in modules_list:
            print "[*] [%s] Executing %s on %s" % (f_vm['name'],mod,f_vm['profile'])
            DataBase.change_analysis_status(f_sample_id,'Executing %s on %s' % (mod,f_vm['profile']))
            logging.info("[*] [%s] Executing %s" % (f_vm['name'],mod))                        
            module_handle = importlib.import_module('code_extractors.' + mod,mod)
            run = getattr(module_handle,'_run')
            run(f_vm['name'],f_vm['profile'],vmem_path,workdir,f_sample_id)             
            print "[*] [%s] [DONE] Executing %s" % (f_vm['name'],mod)            
            logging.info("[*] [%s] [DONE] Executing %s" % (f_vm['name'],mod))
    
        print "[*] PROCESSING COMPLETED [*]"
        logging.info("[*] [%s] PROCESSING OF SAMPLE COMPLETED (sample ID: %d) [*]" % (f_vm['name'],f_sample_id))
        
        #Release VM lock (VM is now ready for next analysis)
        lock_vmindex[f_vm['name']].release()  

        #Set analysis as completed    
        DataBase.change_analysis_status(f_sample_id,'completed')
        
        machine_statistics[f_vm['name']]['samples_analyzed'] = machine_statistics[f_vm['name']]['samples_analyzed'] + 1
        
        cleanup(f_vm)
        
        end_time = time.time()
        sample_analysis_time.append(end_time-start_time)
        
    
        return True
    
    else:
        #If the sample could not be sent to VM, machine fail counter is increased and analysis is marked as failed
        print "[!] Could not send file to VM!"
        print "[*] PROCESSING COMPLETED [*]"
        
        
        machine_status_vmindex[f_vm['name']] = machine_status_vmindex[f_vm['name']] + 1
        #logging.error("[!] Increased the fail counter of the following machine: %s to %d") % (f_vm['name'],machine_status_vmindex[f_vm['name']])

        logging.error("[!] Could not send file to VM!")        
        logging.error("[*] PROCESSING OF SAMPLE FAILED (sample ID: %d) [*]" % (f_sample_id))
        
        lock_vmindex[f_vm['name']].release()  
        cleanup(f_vm)
        DataBase.change_analysis_status(f_sample_id,'failed')
        return False
 

def daemonize_queue(vmindex,sleeptime,f_p_name):
    global sample_count
    global queues
    global machine_status_vmindex
    global machine_failure_threshold
    global lock_vmindex

    threads = []    
    
    print "[*] Starting daemonizer thread for %s" % (f_p_name)
    while True:    
        #print '[DEBUG] [%s-Daemonizer] %d > %d' % (f_p_name,queues[f_p_name].size(),len(vmindex[f_p_name]))
        while (not queues[f_p_name].isEmpty()):
            next = queues[f_p_name].dequeue()
            print next
            print vmindex
            foundVM = False
            waitloop = True
            while(waitloop):
                for vm in vmindex[next['target_pool']]:
                    if (not foundVM):
                        if (vm['enabled']):
                            if machine_status_vmindex[vm['name']] < machine_failure_threshold:
                                if not lock_vmindex[vm['name']].locked():
                                    print vm['name'] + " is idle, sending the task to this VM"
                                    logging.info("[*] %s is idle, sending the task to this VM" % (vm['name']))
                                    lock_vmindex[vm['name']].acquire()
                                    vm['status'] == "processing"
                                    t = Thread(target=run_process_on_vm, args=(vm,sleeptime,next['filename'],next['id']))
                                    t.start()
                                    threads.append(t)
                                    foundVM = True
                                else:
                                    print "[*] [%s-Daemonizer] Waiting, All Machines are busy..." % f_p_name
                                    logging.info("[*] [%s-Daemonizer] Waiting, All Machines are busy..." % f_p_name)
                                    
                                    print "[*] Machine failures counter:"
                                    print machine_status_vmindex
                                    logging.info("[*] Machine failures counter:")
                                    logging.info(machine_status_vmindex)
                                    
                                    if (queues[f_p_name].size() == 0):
                                        print "Next sample is last sample in queue"
                                    else:
                                        print "[*] [%s-Daemonizer] %d samples in queue..." % (f_p_name,queues[f_p_name].size() + 1 )
                                        logging.info("[*] [%s-Daemonizer] %d samples in queue..." % (f_p_name,queues[f_p_name].size() + 1 ))
        
                if (foundVM):
                    waitloop = False
                time.sleep(10)
        
        print '[!!] [%s-Daemonizer] Queue is now empty, waiting for new samples...' % f_p_name
        logging.info('[!!] [%s-Daemonizer] Queue is now empty, waiting for new samples...' % f_p_name)  
        time.sleep(15)     


def daemon_enqueue_new_samples():
    global active_pools
    global queues
    
    while True:
        samples_to_process = DataBase.get_waiting_sample_queue()
        
        for entry in samples_to_process:                
            DataBase.change_analysis_status(entry['id'],'enqueued')
            for pool_name in active_pools:
                sample_entry = {}
                sample_entry['filename'] = entry['filename']
                sample_entry['sha256'] = entry['sha256']
                sample_entry['md5'] = entry['md5']
                sample_entry['id'] = entry['id']
                sample_entry['target_pool'] = pool_name
                
                print '[*] Enqueueing %s in pool %s ' % (sample_entry['md5'],pool_name)
                
                #q.enqueue(sample_entry)     
                queues[pool_name].enqueue(sample_entry)
        
        time.sleep(10)
        print '[*] [daemon_enqueue_new_samples] Looking for samples to enqueue'

def main():
    read_config()
        
    logging.basicConfig(filename=log_path + '/VolatilityBot.log', level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    logging.info('======= VolatilityBot Initialized =======')
    
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-f',"--filename", help="The Executable you want to submit")
    parser.add_argument("-s","--sleep", help="How much time to wait, in seconds")
    parser.add_argument('-r', action='store_true',help="Submit a directory, as opposed to -f (file)")
    parser.add_argument('-x', action='store_true', help="Delete original file after submission")    
    parser.add_argument('-e', action='store_true', help="Enqueue files, but do not analyze them now")
    parser.add_argument('-D', action='store_true', help="Execute in daemon mode")
    parser.add_argument('-S', action='store_true', help="Skip existing samples")
    parser.add_argument('-Q', action='store_true', help="Re-enqueue failed samples")
    parser.add_argument('-t','--tags', help='Sample tags, separated by commas i.e: Dyre,Upatre')
    args = parser.parse_args()
    

    global init_machine
    global revert
    global start
    global suspend
    global get_mem_path
    global modules_list    
    global cleanup
    global conf_path
    global machine_failure_threshold
    global active_pools
    global queues
    
    
    print '[*] Machines failure threshold is %d' % (machine_failure_threshold)
    logging.info('[*] Machines failure threshold is %d' % (machine_failure_threshold))

    machine_engine = importlib.import_module('machines.' + machine_type,machine_type)
    init_machine = getattr(machine_engine,'_init')
    revert = getattr(machine_engine,'_revert')
    start = getattr(machine_engine,'_start')
    suspend = getattr(machine_engine,'_suspend')
    get_mem_path = getattr(machine_engine,'_get_mem_path')
    cleanup = getattr(machine_engine,'_cleanup')
    
    modules_list = CodeExtractor._load_config()
    
    vmindex = init_machine()

    print '[*] Loaded active machine resource pools: %s' % active_pools
    
    print json.dumps(vmindex,indent=4)
    #print vmindex


    global lock_vmindex 
    global machine_status_vmindex
    global machine_statistics    
    
    lock_vmindex = {}   
    for pool in vmindex:
        for vm in vmindex[pool]:
            print vm
            lock_vmindex[vm['name']] = threading.Lock()	
            machine_status_vmindex[vm['name']] = 0
            statistic_entry = { 'samples_analyzed' : 0 , 'samples_failed' : 0 }        
            machine_statistics[vm['name']] = statistic_entry
            machine_statistics[vm['name']]['samples_analyzed']
            machine_statistics[vm['name']]['samples_failed']

 
     
    class Queue:
        def __init__(self):
            self.items = []
    
        def isEmpty(self):
            return self.items == []
    
        def enqueue(self, item):
            self.items.insert(0,item)
    
        def dequeue(self):
            return self.items.pop()
    
        def size(self):
            return len(self.items)

    start_time = datetime.now()



    q = Queue()
    
    queues = {}
    for pool_name in active_pools:
        queues[pool_name] = Queue()
        

    sample_count = 0
    threads = []


    if (args.e):
            print '[!!] Enqueuing new samples:'
            logging.info('[!!] Enqueuing new samples:')   
            
            if (args.r):
                print '[!!] Enqueuing folder'
                logging.info('[!!] Enqueuing folder')   

                path = args.filename 
                for root, directories, files in os.walk(path):
                    for filename in files:
        

                        
                        sample_entry = {}
                        
                        try:
                            pe =  pefile.PE(root + '/' + filename,fast_load=True)
                            isPE = True
                        except:
                            isPE = False
                            
                        if (isPE):
                            #print root + '/' + filename + " is PE"
                            file_sha256 = sample.calc_SHA256(root + '/' + filename)
                            file_md5 = sample.calc_MD5(root + '/' + filename)     
                            sample._copy_sample_to_store(root + '/' + filename)
                            #Calc imphash, or make the parameter = fail
                            f_ephash = ephash.calc_ephash(root + '/' + filename)
                            #Calc EPhash, or make the parameter = fail       
                            f_imphash = ephash.calc_imphash(root + '/' + filename)
                            
                            sample_id = DataBase.add_sample(file_sha256,file_md5,f_imphash,f_ephash,VolatilityBot_Home + "/Store/" + file_sha256 + "/" + file_sha256 + ".bin")                             
                            
                            print "[*] Enqueuing %s:" % (filename)
                            
                            logging.info("[*] Enqueuing %s:" % (filename))
                        

                            if args.x:
                                print "[!!!!] Deleting original sample for  sample ID is %s" % (str(sample_id))
                                logging.info("[!!!!] Deleting original sample for  sample ID is %s" % (str(sample_id)))
                                os.remove(root + '/' + filename)
                            
                            print "[!!] This sample ID is %s" % (str(sample_id))
                            logging.info("[*] This sample ID is %s" % (str(sample_id)))
                            
                            #Check if sample exists...
                            if args.S:
                                if DataBase.check_if_sample_exists(file_sha256):
                                     logging.info("[!!] Sample %s was skipped, because sample exists in DB and  -s flag was set" % (file_sha256))
                                     continue
                                
                            if (not args.tags == None ):
                                #print args.tags
                                tags_arr = args.tags.split(',')
                                for tag in tags_arr:
                                    logging.info("Adding tag %s to %s" % (tag,sample_id))
                                    DataBase.add_tag(tag,sample_id)
                                   
                
                
            else:
                if not os.path.exists(args.filename):
                    print '[!] No file given, or file does not exist'
                    exit(256)
                path = args.filename    
                try:
                    pe =  pefile.PE(path,fast_load=True)
                    isPE = True
                except:
                    isPE = False
                if (isPE):
                    print '[!!] Enqueuing file %s' % (path)
                    logging.info('[!!] Enqueuing file %s' % (path)) 
    
                    file_sha256 = sample.calc_SHA256(path)
                    sample._copy_sample_to_store(path)
                    #Calc imphash, or make the parameter = fail
                    f_ephash = ephash.calc_ephash(path)
                    #Calc EPhash, or make the parameter = fail       
                    f_imphash = ephash.calc_imphash(path)                    
                    sample_id = DataBase.add_sample( sample.calc_SHA256(path),sample.calc_MD5(path),f_imphash,f_ephash,VolatilityBot_Home + "/Store/" + file_sha256 + "/" + file_sha256 + ".bin")   

                    if args.x:
                        print "[!!!!] Deleting original sample for  sample ID is %s" % (str(sample_id))
                        logging.info("[!!!!] Deleting original sample for  sample ID is %s" % (str(sample_id)))
                        os.remove(path)
                        
                    
                else:
                    print '[!!] File %s is not a valid PE!' % (path)
                    logging.info('[!!] File %s is not a valid PE!' % (path))                     
                    
            exit(0)                            
            
    elif (args.D):
            print '[!!] VolatilityBot loaded in Daemon mode'
            logging.info('[!!] VolatilityBot loaded in Daemon mode')       
            
            sleeptime = args.sleep
            if sleeptime is None:
                print '[!!] No sleep time specified, specify with --sleep or -s ABORTING.'
                logging.info('[!!] No sleep time specified, specify with --sleep or -s ABORTING.')
                exit(111)            
            elif not sleeptime.isdigit():
                print '[!!] Sleep time should be a number, in seconds ABORTING'
                logging.info('[!!] Sleep time should be a number, in seconds ABORTING')
                exit(112)                                    
            
            #Get all sample in enqueued state, and change them to waiting
            DataBase.reenqueue_enqueued_samples()
            
            
            samples_to_process = DataBase.get_waiting_sample_queue()
            for pool_name in active_pools:
                for entry in samples_to_process:
                    sample_entry = {}
                    sample_count = sample_count + 1
                    sample_entry['filename'] = entry['filename']
                    sample_entry['sha256'] = entry['sha256']
                    sample_entry['md5'] = entry['md5']
                    sample_entry['id'] = entry['id']
                    sample_entry['target_pool'] = pool_name
                    
                    print '[*] Enqueueing %s in pool %s ' % (sample_entry['md5'],pool_name)
                    
                    
                    #q.enqueue(sample_entry)     
                    queues[pool_name].enqueue(sample_entry)
                
            global lock_vmindex			
        
            t = Thread(target=daemon_enqueue_new_samples)
            t.start()
            threads.append(t)
        
            for p_name in active_pools:
                t = Thread(target=daemonize_queue, args=(vmindex,sleeptime,p_name))
                t.start()
                threads.append(t)
                
    elif (args.Q):
        print '[!] Going to re-enqueue failed samples:'
        new_queue = DataBase.get_failed_sample_queue()

        q_size = len(new_queue)
        if q_size > 0:
            print '[*] %d samples in queue' % q_size
            print new_queue
        else:
            print '[!] No failed samples in queue'

        DataBase.reenqueue_failed_samples()



    else:
        print '[!!!] [Error] Invalid parameters were set, either enqueue sample or Launch VolatilityBot Daemon.'


    [x.join() for x in threads] 
   
if __name__ == '__main__':
    main()  


