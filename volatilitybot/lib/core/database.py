#! /usr/bin/python

import datetime
import logging

from elasticsearch import Elasticsearch, NotFoundError

from volatilitybot.conf.config import ES_HOSTS


class DataBaseConnection:
    def __init__(self):
        self.es = Elasticsearch(ES_HOSTS)

    def sample_exists(self, malware_sample):
        try:
            self.es.get(index='volatilitybot-samples', doc_type='sample', id=malware_sample.sample_data['sha256'])
            return True
        except NotFoundError:
            return False

    def add_sample(self, malware_sample):
        logging.info("[*] New sample!")
        sha256 = malware_sample.sample_data['sha256']
        self.es.index(index='volatilitybot-samples',doc_type='sample',id=sha256, body=malware_sample.sample_data)
        return sha256

    def add_dump(self, malware_dump):
        # create an Insert object

        sha256 = malware_dump.dump_data['sha256']
        self.es.index(index='volatilitybot-dumps',doc_type='dump',id=sha256, body=malware_dump.dump_data)
        return sha256

    def add_tag(self, set_tag, malware_sample):
        """
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
        """
        return True

