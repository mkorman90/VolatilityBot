#! /usr/bin/python
import datetime
import json
import logging
import os
import shutil

import pendulum
from elasticsearch import NotFoundError

from volatilitybot.lib.common.pe_utils import static_analysis
from volatilitybot.lib.core.es_utils import DataBaseConnection

from volatilitybot.conf import config
from volatilitybot.lib.common.utils import calc_md5, calc_sha256, calc_sha1, calc_ephash, calc_imphash

VolatilityBot_Home = ""


class MalwareSample:
    def __init__(self, file_path):
        self.file_path = file_path
        self.sample_data = {}

        sha256 = calc_sha256(self.file_path)
        self.id = sha256

        # Move file to store
        target_directory = os.path.join(config.STORE_PATH, sha256)
        target_name = os.path.join(config.STORE_PATH, sha256, sha256 + '.bin')

        if not os.path.exists(target_directory):
            os.makedirs(target_directory)
            shutil.copyfile(self.file_path, target_name)
            logging.info('Stored file at {}'.format(target_directory))

        # Change file path to the new one in store
        self.file_path = target_name
        logging.info('File was already present at {}'.format(target_directory))

    def get_sample_data(self):
        db = DataBaseConnection()
        sample_sha256 = calc_sha256(self.file_path)
        try:
            res = db.es.get(index='volatilitybot-samples', doc_type='sample', id=sample_sha256)
            self.sample_data.update(res['_source'])

        except NotFoundError:
            self.sample_data.update({'ephash': calc_ephash(self.file_path),
                                     'file_path': self.file_path,
                                     'file_type': None,
                                     'imphash': calc_imphash(self.file_path),
                                     'md5': calc_md5(self.file_path),
                                     'sha1': calc_sha1(self.file_path),
                                     'sha256': calc_sha256(self.file_path),
                                     'timestamp': pendulum.now().isoformat(),
                                     'id': self.id,
                                     'status': 'waiting'})

    def report(self):
        """
        Add sample to store, and enqueue it in DB
        :return:
        """

        # Load connectivity to DB, and enqueue the sample
        db = DataBaseConnection()
        sample = db.sample_exists(self)

        if sample:
            logging.info('Sample already exists!')
            return False
        else:

            # Add static analysis result to sample
            self.sample_data.update({
                'static_analysis': static_analysis(self.file_path)
            })

            logging.info('Adding new sample')
            db.add_sample(self)
            return True

    def print_sample_details(self):
        logging.info(json.dumps(self.sample_data, indent=4))


class SampleDump:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.dump_data = {
            'timestamp': pendulum.now().isoformat()
        }

        self.id = None
        self.parent_sample_id = None
        self.md5 = None
        self.sha256 = None
        self.imphash = None
        self.ephash = None
        self.process_name = None
        self.source = None

        self.timestamp = datetime.datetime.now()
        return

    def calculate_hashes(self):
        self.dump_data.update({
            'md5': calc_md5(self.binary_path),
            'sha1': calc_sha1(self.binary_path),
            'sha256': calc_sha256(self.binary_path),
            'imphash': calc_imphash(self.binary_path),
            'ephash': calc_ephash(self.binary_path)
        })

    def report(self):
        # Add static analysis result to sample
        db = DataBaseConnection()
        sample = db.dump_exists(self)

        if sample:
            logging.info('Dump already exists!')
            return False

        self.dump_data.update({
            'static_analysis': static_analysis(self.binary_path)
        })
        db.add_dump(self)
        return True

