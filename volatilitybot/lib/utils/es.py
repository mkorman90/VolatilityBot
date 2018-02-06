from elasticsearch import Elasticsearch

from volatilitybot.conf.config import ES_HOSTS


class EsInstance:
    def __init__(self):
        self.es = Elasticsearch(ES_HOSTS)

    def initialize_es(self):
        if not self.es.indices.exists('volatilitybot-samples'):
            self.es.indices.create('volatilitybot-samples')

        if not self.es.indices.exists('volatilitybot-dumps'):
            self.es.indices.create('volatilitybot-dumps')
