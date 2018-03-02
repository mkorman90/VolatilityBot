import json

from volatilitybot.lib.utils.postgresql import re_enqueue_all_sent


def main():
    re_enqueue_all_sent()


if __name__ == '__main__':
    main()
