#! /usr/bin/python
import datetime

import logging
from sqlalchemy import create_engine
from sqlalchemy import MetaData, Table
from sqlalchemy.orm import sessionmaker

from conf.config import DB_ENGINE


class DataBaseConnection:
    def __init__(self):
        self.engine = create_engine(DB_ENGINE, echo=False, connect_args={'check_same_thread': False})
        metadata = MetaData(bind=self.engine)

        self.samplesTable = Table("sample_malwaresample", metadata, autoload=True, schema="main")
        self.dumpsTable = Table("sample_dump", metadata, autoload=True, schema="main")
        self.tagsTable = Table("sample_tag", metadata, autoload=True, schema="main")

    def sample_exists(self, malware_sample):
        db_session = sessionmaker(bind=self.engine)
        session = db_session()
        res = session.query(self.samplesTable).filter(self.samplesTable.c.sha256 == malware_sample.sha256).first()
        return res

    def add_sample(self, malware_sample):
        logging.info("[*] New sample!")
        db_session = sessionmaker(bind=self.engine)
        session = db_session()
        current_time = datetime.datetime.now()
        ins = self.samplesTable.insert()
        # add values to the Insert object
        new_sample = ins.values(timestamp=current_time, sha256=malware_sample.sha256, md5=malware_sample.md5,
                                imphash=malware_sample.imphash, ephash=malware_sample.ephash,
                                binary_path=malware_sample.file_path, status='waiting')

        # create a database connection
        conn = self.engine.connect()
        # add user to database by executing SQL

        result = conn.execute(new_sample)

        conn.close()
        session.close()

        return result.lastrowid

    def add_dump(self, malware_dump):
        # create an Insert object
        current_time = datetime.datetime.now()
        ins = self.dumpsTable.insert()
        # add values to the Insert object
        new_dump = ins.values(sample_id_id=malware_dump.parent_sample_id, md5=malware_dump.md5,
                              ephash=malware_dump.ephash, imphash=malware_dump.imphash, sha256=malware_dump.sha256,
                              process_name=malware_dump.process_name, source=malware_dump.source,
                              binary_path=malware_dump.binary_path, timestamp=current_time)
        # create a database connection
        conn = self.engine.connect()
        # add user to database by executing SQL
        result = conn.execute(new_dump)
        conn.close()

        return result.lastrowid

    def add_tag(self, set_tag, malware_sample):
        # Find all existing tags for that sample, and remove from the to_add list existing ones.
        tag_exists = False

        db_session = sessionmaker(bind=self.engine)
        session = db_session()

        for instance in session.query(self.tagsTable).filter(self.tagsTable.c.sample_id_id == malware_sample.id).all():
            if instance.tag == set_tag:
                tag_exists = True

        if not tag_exists:
            # Add the new ones
            ins = self.tagsTable.insert()
            new_tag = ins.values(sample_id_id=malware_sample.id, tag=set_tag)
            # create a database connection
            conn = self.engine.connect()
            # add user to database by executing SQL
            conn.execute(new_tag)
            conn.close()
            session.close()
            logging.info('[*] Tag {} added to sample'.format(set_tag))
            return True
        else:
            logging.info('[*] Sample alread has tag: {} '.format(set_tag))
            return False

