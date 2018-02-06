import json

from volatilitybot.lib.utils.postgresql import get_sample_queue


def main():
    queue = get_sample_queue(status='all')
    if queue:
        [print(x) for x in queue]


if __name__ == '__main__':
    main()
