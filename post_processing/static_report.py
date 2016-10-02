# -*- coding: utf-8 -*-
"""
Created on Thu Feb 12 00:08:43 2015

@author: Martin
"""
import logging
import pefile
from pefile import PEFormatError

NAME = 'static_report'
TIMEOUT = 60


def execute(sample_dump_instance):
    logging.info("[*] Performing static analysis for {}".format(sample_dump_instance.binary_path))
    try:
        pe = pefile.PE(sample_dump_instance.binary_path)
        return pe.dump_info()
    except PEFormatError:
        return None
