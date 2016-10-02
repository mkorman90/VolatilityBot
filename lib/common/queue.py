from sqlalchemy.orm import sessionmaker

from lib.common.utils import calc_sha256
from lib.core.sample import MalwareSample
from lib.core.database import DataBaseConnection

class Queue:
    def __init__(self):
        self.items = []

    def isEmpty(self):
        return self.items == []

    def enqueue(self, item):
        self.items.insert(0, item)

    def dequeue(self):
        return self.items.pop()

    def size(self):
        return len(self.items)

    def get_waiting_sample_queue(self):
        all_samples = []
        db_connection = DataBaseConnection()

        db_session = sessionmaker(bind=db_connection.engine)
        session = db_session()
        for instance in session.query(db_connection.samplesTable).filter(db_connection.samplesTable.c.status == 'waiting').all():
            sample_entry = MalwareSample(instance.binary_path)
            sample_entry.sha256 = calc_sha256(instance.binary_path)
            sample_entry.get_sample_data()
            self.enqueue(sample_entry)
        session.close()
        return
