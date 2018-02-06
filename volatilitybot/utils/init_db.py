import os
import py2neo
import shutil

from volatilitybot.conf.config import PSQL_DB_NAME, PSQL_TABLE_NAME, STORE_PATH
from volatilitybot.lib.utils.es import EsInstance
from volatilitybot.lib.utils.postgresql import db_cursor
from volatilitybot.conf.config import NEO4j_USER, NEO4j_PASS
from volatilitybot.post_processing.utils.dpa_utils import DPA_FUNCTIONS_INDEX

SCHEMA = """
        CREATE TABLE {} (
                sha256 varchar(64) NOT NULL,
                PRIMARY KEY (sha256),
                sample_path varchar(256) NOT NULL,
                status varchar(16) NOT NULL,
                submitted timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
                last_status_update timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
        )
""".format(PSQL_TABLE_NAME)

print('!!!! THIS WILL DELETE ALL THE DATABASE INFO, ALONG WITH SAMPLES IN THE STORE! ANSWER "YES" TO CONTINUE')

response = input("Confirm: ")
if response != 'YES':
    print('phew! nothing was deleted...')
    exit(256)

print('Removing files from store:')
for dir in os.scandir(STORE_PATH):
    print(dir.path)
    shutil.rmtree(dir.path)

print('Recreating postgresql DB')
with db_cursor() as cur:
    cur.execute('DROP DATABASE {}'.format(PSQL_DB_NAME))
    cur.execute('CREATE DATABASE {}'.format(PSQL_DB_NAME))

with db_cursor(dbname=PSQL_DB_NAME) as cur:
    cur.execute(SCHEMA)

print('Recreating ES indices')
es_instance = EsInstance()
es_instance.initialize_es()

if es_instance.es.indices.exists(DPA_FUNCTIONS_INDEX):
    es_instance.es.indices.delete(DPA_FUNCTIONS_INDEX)

print('Deleting neo4j data')
py2neo.authenticate("localhost:7474", NEO4j_USER, NEO4j_PASS)
graph = py2neo.Graph("http://localhost:7474/db/data/")
graph.delete_all()

try:
    graph.schema.create_index('sample', 'sample_hash')
except Exception as ex:
    print(ex)
    if ex.__class__.__name__ != 'ConstraintViolationException':
        exit(100)
    print('sample index already exists...')

try:
    graph.schema.create_index('function', 'fhash')
except Exception as ex:
    print(ex)
    if ex.__class__.__name__ != 'ConstraintViolationException':
        exit(100)

try:
    graph.schema.create_index('dump', 'dump_hash')
except Exception as ex:
    print(ex)
    if ex.__class__.__name__ != 'ConstraintViolationException':
        exit(100)
