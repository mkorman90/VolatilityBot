from contextlib import contextmanager

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from volatilitybot.conf.config import PSQL_USERNAME, PSQL_HOSTNAME, PSQL_PASSWORD, PSQL_DB_NAME, PSQL_TABLE_NAME


@contextmanager
def db_cursor(dbname=None):
    if not dbname:
        dsn = "user='{}' host='{}' password='{}'".format(PSQL_USERNAME, PSQL_HOSTNAME, PSQL_PASSWORD)
    else:
        dsn = "user='{}' dbname='{}' host='{}' password='{}'".format(PSQL_USERNAME, PSQL_DB_NAME, PSQL_HOSTNAME,
                                                                     PSQL_PASSWORD)

    try:
        conn = psycopg2.connect(dsn)
    except Exception as ex:
        raise Exception('Could not connect to DB: {}'.format(ex))

    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()
    yield cursor
    cursor.close()
    conn.close()


def get_sample_queue(status='waiting'):
    with db_cursor(dbname=PSQL_DB_NAME) as cur:
        if status == 'all':
            cur.execute('select * from {}'.format(PSQL_TABLE_NAME))
        else:
            cur.execute('select * from {} where status = %s'.format(PSQL_TABLE_NAME), (status,))
        results = cur.fetchall()

    if results:
        return [{'sha256': sha256,
                 'sample_path': sample_path,
                 'status': status,
                 'submitted': submitted,
                 'last_status_update': last_status_update} for
                sha256, sample_path, status, submitted, last_status_update in results]
    return None


def update_sample_status(sample_sha256, status):
    print('settings status of {} to: {}'.format(sample_sha256,status))
    with db_cursor(dbname=PSQL_DB_NAME) as cur:
        result = cur.execute('update {} set status = %s where sha256 = %s'.format(PSQL_TABLE_NAME),
                             (status, sample_sha256))
    return True
