#! /usr/bin/python

from sqlalchemy import create_engine
from sqlalchemy import MetaData, Column, Table, ForeignKey
from sqlalchemy import Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy import update
from time import gmtime, strftime
from sqlalchemy import exc
import datetime
import time

import os
import yaml

engine_path = ""
samplesTable = ""
dumpsTable = ""
tagsTable = ""
engine = ""
metadata = ""
max_attempt_threshold = 5

def _load_config():
  global engine_path
  global samplesTable
  global dumpsTable
  global tagsTable
  global engine
  global metadata
  global max_attempt_threshold
  
  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	engine_path = dataMap['mainconfig']['general']['db_engine']

	#print "[!] Using engine: %s" % (engine_path)        

	#try:
	success = False
	attempt_count = 0
 
	while ((attempt_count <= max_attempt_threshold) and (not success)):
         try:
             attempt_count += 1
             engine = create_engine(engine_path,echo=False,connect_args={'check_same_thread':False})
             metadata = MetaData(bind=engine)

             samplesTable = Table("sample_malwaresample", metadata, autoload=True, schema="main")
             dumpsTable = Table("sample_dump", metadata, autoload=True, schema="main")
             tagsTable =  Table("sample_tag", metadata, autoload=True, schema="main")
             
             success = True
         except exc.OperationalError:
             print '[!!] SQLAlchemy OperationalError, sleeping 5 seconds and retrying:'
             time.sleep(5)
             engine = create_engine(engine_path,echo=False,connect_args={'check_same_thread':False})
             metadata = MetaData(bind=engine)

             samplesTable = Table("sample_malwaresample", metadata, autoload=True, schema="main")
             dumpsTable = Table("sample_dump", metadata, autoload=True, schema="main")
             tagsTable =  Table("sample_tag", metadata, autoload=True, schema="main")
        
	
 
 

	#except:
      #   print "[!!!] Corrupted DB was found, Resetting DB:"
      #   print "    Please recreate DB using db_builder.py    "
      #   exit()
 
	return True       
 
  return False



def add_sample(f_sha256,f_md5,f_imphash,f_ephash,f_binary_path):
    _load_config()
    global max_attempt_threshold
    attempt_count = 0
    success = False
    
    try:    
        Session = sessionmaker(bind=engine)
        session = Session()
        res = session.query(samplesTable).filter(samplesTable.c.sha256==f_sha256).first()
        print "[*] sample already exists! id is: %s" %  (str(res.id))
        return res.id
    except:       
        # create an Insert object    
        print "[*] New sample!"
        current_time = datetime.datetime.now()
        ins = samplesTable.insert()
        # add values to the Insert object
        new_sample = ins.values(timestamp=current_time,sha256=f_sha256,md5=f_md5,imphash=f_imphash,ephash=f_ephash,binary_path=f_binary_path,status='waiting')
     
        # create a database connection
        conn = engine.connect()
        # add user to database by executing SQL
        
        
        while ((attempt_count <= max_attempt_threshold) and (not success)):
            try:
                attempt_count += 1
                result = conn.execute(new_sample)
                success = True
            except exc.OperationalError:
                print '[!!] SQLAlchemy OperationalError, sleeping 5 seconds and retrying:'
                time.sleep(5)
                result = conn.execute(new_sample)
        
        conn.close()
        session.close()
        
        return result.lastrowid


def check_if_sample_exists(f_sha256):
    _load_config()
    try:    
        Session = sessionmaker(bind=engine)
        session = Session()
        res = session.query(samplesTable).filter(samplesTable.c.sha256==f_sha256).filter(samplesTable.c.status=='completed').first()
        print "[*] sample already exists! id is: %s" %  (str(res.id))
        session.close()
        return True
    except:
        return False

  
def add_dump(f_sample_id,f_md5,f_sha256,f_ephash,f_imphash,f_process_name,f_source,f_binary_path):
    _load_config()
    # create an Insert object
    current_time = datetime.datetime.now()
    ins = dumpsTable.insert()
    # add values to the Insert object
    new_dump = ins.values(sample_id_id=f_sample_id,md5=f_md5,ephash=f_ephash,imphash=f_imphash,sha256=f_sha256,process_name=f_process_name,source=f_source,binary_path=f_binary_path,timestamp=current_time)
     
    # create a database connection
    conn = engine.connect()
    # add user to database by executing SQL
    conn.execute(new_dump)
    conn.close()

def change_analysis_status(f_sample_id,f_status):
    _load_config()
    # create an Update object
    #current_time = datetime.datetime.now()
    
    stmt = samplesTable.update().where(samplesTable.c.id==f_sample_id).values(status=f_status)
    conn = engine.connect()

    # Update sample status
    conn.execute(stmt)   
    conn.close()


def get_failed_sample_queue():
    _load_config()
    
    all_samples = []
    Session = sessionmaker(bind=engine)
    session = Session()
    for instance in session.query(samplesTable).filter(samplesTable.c.status == 'failed').all():    
        sample_entry = {}
        sample_entry['filename'] = instance.binary_path
        sample_entry['sha256'] = instance.sha256
        sample_entry['md5'] = instance.md5
        sample_entry['id'] = instance.id
        all_samples.append(sample_entry)
    session.close()
    return all_samples    

def get_waiting_sample_queue():
    _load_config()
    
    all_samples = []
    Session = sessionmaker(bind=engine)
    session = Session()
    for instance in session.query(samplesTable).filter(samplesTable.c.status == 'waiting').all():    
        sample_entry = {}
        sample_entry['filename'] = instance.binary_path
        sample_entry['sha256'] = instance.sha256
        sample_entry['md5'] = instance.md5
        sample_entry['id'] = instance.id
        all_samples.append(sample_entry)
    session.close()
    return all_samples    

def reenqueue_enqueued_samples():
    _load_config()
    
    Session = sessionmaker(bind=engine)
    session = Session()
    for instance in session.query(samplesTable).filter(samplesTable.c.status == 'enqueued').all():    
        print '[*] Re-Enqueuing %s (%d) SHA256: %s' % (instance.binary_path,instance.id,instance.sha256)
        change_analysis_status(instance.id,'waiting')
    session.close()
    return True    

def reenqueue_failed_samples():
    _load_config()

    Session = sessionmaker(bind=engine)
    session = Session()
    for instance in session.query(samplesTable).filter(samplesTable.c.status == 'failed').all():
        print '[*] Re-Enqueuing %s (%d) SHA256: %s' % (instance.binary_path,instance.id,instance.sha256)
        change_analysis_status(instance.id,'waiting')
    session.close()
    return True

def add_tag(set_tag,f_sample_id):
    _load_config()
	#Find all existing tags for that sample, and remove from the to_add list existing ones.
    Session = sessionmaker(bind=engine)
    session = Session()
    tag_exists = False
    for instance in session.query(tagsTable).filter(tagsTable.c.sample_id_id == f_sample_id).all():
		if (instance.tag == set_tag):
			tag_exists = True
   


    if not tag_exists:
    	#Add the new ones
    	ins = tagsTable.insert()
    	new_tag = ins.values(sample_id_id=f_sample_id,tag=set_tag)
    	# create a database connection
    	conn = engine.connect()
    	# add user to database by executing SQL
    	conn.execute(new_tag)  
    	conn.close()
    	session.close()
    	print "[*] Tag %s added to sample" % (set_tag)  
    	return True
    else:
    	print "[*] Sample alread has tag: %s " % (set_tag)   
    	return False

