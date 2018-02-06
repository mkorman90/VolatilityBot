import sys
import psycopg2

from volatilitybot.conf.config import PSQL_DB_NAME, PSQL_TABLE_NAME
from volatilitybot.lib.utils.file_utils import copy_to_store, generate_file_sha256
from volatilitybot.lib.utils.postgresql import db_cursor


def main():
    file_path = sys.argv[1]
    print('Submitting {}'.format(file_path))

    sha256 = generate_file_sha256(file_path)
    print(sha256)

    sample_path = copy_to_store(file_path, sha256)

    with db_cursor(dbname=PSQL_DB_NAME) as cur:
        try:
            result = cur.execute("INSERT INTO volatilitybot_queue (sha256, sample_path, status) VALUES (%s, %s, %s)",
                                 (sha256,
                                  sample_path, 'waiting'))
        except psycopg2.IntegrityError:
            print('Sample is already in DB!')


if __name__ == '__main__':
    main()
