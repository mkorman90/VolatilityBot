from sqlalchemy.orm import sessionmaker

from volatilitybot.lib.common.utils import calc_sha256
from volatilitybot.lib.core.es_utils import DataBaseConnection
from volatilitybot.lib.core.sample import MalwareSample


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
        db = DataBaseConnection()

        res = db.es.search(index="volatilitybot-samples", doc_type="sample",
                        body={"query": {"match": {"status": "waiting"}}})

        hits = res['hits']['hits']

        if not hits:
            return

        for doc in hits:
            doc_data = doc['_source']
            sample_entry = MalwareSample(doc_data.get('file_path'))
            sample_entry.sha256 = calc_sha256(doc_data.get('file_path'))
            sample_entry.get_sample_data()
            self.enqueue(sample_entry)
