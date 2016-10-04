#! /usr/bin/python
import logging
import os
import shutil

import datetime

from conf.config import STORE_PATH
from lib.common.utils import calc_md5, calc_sha256, calc_sha1, calc_ephash, calc_imphash
from lib.core.database import DataBaseConnection

VolatilityBot_Home = ""


class MalwareSample():
    def __init__(self, file_path):
        self.md5 = None
        self.sha1 = None
        self.sha256 = None
        self.imphash = None
        self.ephash = None

        self.timestamp = None
        self.id = None
        self.status = None

        self.file_path = file_path
        self.file_type = None

    def get_sample_data(self):
        if self.file_path.startswith(os.path.abspath(STORE_PATH) + '/'):
            logging.info('Sample is already in store, going to retrieve hashes from DB')
            db_connection = DataBaseConnection()
            sample = db_connection.sample_exists(self)
            self.id = sample[0]
            self.timestamp = sample[1]
            self.sha256 = sample[2]
            self.ephash = sample[3]
            self.imphash = sample[4]
            self.status = sample[5]
            self.md5 = sample[6]
        else:
            self.md5 = calc_md5(self.file_path)
            self.sha1 = calc_sha1(self.file_path)
            self.sha256 = calc_sha256(self.file_path)
            self.ephash = calc_ephash(self.file_path)
            self.imphash = calc_imphash(self.file_path)
        return

    def enqueue(self):
        """
        Add sample to store, and enqueue it in DB
        :return:
        """
        target_directory = os.path.join(STORE_PATH, self.sha256)
        if not os.path.exists(target_directory):
            os.makedirs(target_directory)
            target_name = os.path.join(STORE_PATH, self.sha256, self.sha256 + '.bin')
            shutil.copyfile(self.file_path, target_name)
            logging.info('Stored file at {}'.format(target_directory))

            # Change file path to the new one in store
            self.file_path = target_name
        else:
            logging.info('Folder already exists, the store is not in sync with the DB (Sample: {})'.format(self.sha256))

        # Load connectivity to DB, and check if there are Malware samples in queue
        db_connection = DataBaseConnection()
        sample = db_connection.sample_exists(self)

        if sample:
            logging.info('Sample already exists!')
            return False
        else:
            logging.info('Adding new sample')
            db_connection.add_sample(self)
            return True

    def sample_data_as_dict(self):
        return {'id': self.id, 'timestamp': self.timestamp, 'md5': self.md5, 'sha256': self.sha256, 'ephash': self.ephash, 'imphash': self.imphash}

    def set_status(self, f_status):
        """
        Changes the status of the sample in DB and object
        :param f_status: ['completed','failed']
        :return:
        """
        db_connection = DataBaseConnection()
        self.status = f_status
        stmt = db_connection.samplesTable.update().where(db_connection.samplesTable.c.id == self.id).values(
            status=f_status)
        conn = db_connection.engine.connect()
        # Update sample status
        conn.execute(stmt)
        conn.close()

    def print_sample_details(self):
        logging.info('Sample ID: {}, SHA256: {}'.format(self.id, self.sha256))


class SampleDump:
    def __init__(self,binary_path):
        self.id = None
        self.parent_sample_id = None
        self.md5 = None
        self.sha256 = None
        self.imphash = None
        self.ephash = None
        self.process_name = None
        self.source = None
        self.binary_path = binary_path
        self.timestamp = datetime.datetime.now()
        return

    def calculate_hashes(self):
        self.md5 = calc_sha256(self.binary_path)
        self.sha256 = calc_sha256(self.binary_path)
        self.ephash = calc_ephash(self.binary_path)
        self.imphash = calc_imphash(self.binary_path)

    def report(self):
        pass