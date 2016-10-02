# -*- coding: utf-8 -*-
"""
Created on Wed Feb 11 23:02:36 2015

@author: Martin
"""

from lib.common.utils import yara_scan_file

NAME = None
TIMEOUT = 60


def scan_with_yara(sample_dump_instance):
    return yara_scan_file(sample_dump_instance)


