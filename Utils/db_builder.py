# -*- coding: utf-8 -*-
"""
Created on Mon Jan 26 22:29:42 2015

@author: martin
"""

from sqlalchemy import create_engine
from sqlalchemy import MetaData, Column, Table, ForeignKey
from sqlalchemy import Integer, String
from time import gmtime, strftime
import yaml
import os

if os.path.isfile('conf/main.conf'):
    f = open('conf/main.conf')
    dataMap = yaml.safe_load(f)
    f.close()

    engine_path = dataMap['mainconfig']['general']['db_engine']

    engine = create_engine(engine_path,echo=False,connect_args={'check_same_thread':False})
    metadata = MetaData(bind=engine)

samples_table = Table('sample_malwaresample', metadata,
                    Column('id', Integer, primary_key=True),
                    Column('timestamp', String(40)),
                    Column('sha256', String(32)),
                    Column('ephash', String(32)),
                    Column('imphash', String(32)),
                    Column('status', String(16)),
                    Column('md5', String(16)),
                    Column('binary_path', String),
                    sqlite_autoincrement=True)
 
procdumps_table = Table('sample_dump', metadata,
                        Column('id', Integer, primary_key=True),
                        Column('sample_id_id', None, ForeignKey('sample_malwaresample.id')),
                        Column('md5', String, nullable=False),                            
                        Column('sha256', String, nullable=False),                            
                        Column('ephash', String(32)),
                        Column('imphash', String(32)),                        
                        Column('process_name', String, nullable=False),                            
                        Column('source', String, nullable=False),   #Source: injected/DLL/Process
                        Column('binary_path', String, nullable=False),                            
                        Column('timestamp', String, nullable=False)                                                    
                        )

tags_table = Table('sample_tag', metadata,
                                Column('id', Integer, primary_key=True),
                                Column('sample_id_id', None, ForeignKey('sample_malwaresample.id')),
                                Column('tag', String, nullable=False)
                        )
                        



# create tables in database
metadata.create_all()



samplesTable = Table("sample_malwaresample", metadata, autoload=True, schema="main")
dumpsTable = Table("sample_dump", metadata, autoload=True, schema="main")
tagsTable = Table("sample_tag", metadata, autoload=True, schema="main")


def main():
    print "Done"
    
if __name__ == '__main__':
    main()  

