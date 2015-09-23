# -*- coding: utf-8 -*-
"""
Created on Thu Feb 12 00:08:43 2015

@author: Martin
"""
import os
import yaml
import pefile

VolatilityBot_Home = ""
sample_id = ""


def init():
  global VolatilityBot_Home
  if os.path.isfile('conf/main.conf'):
	f = open('conf/main.conf')
	# use safe_load instead load
	dataMap = yaml.safe_load(f)
	f.close()

	VolatilityBot_Home = dataMap['mainconfig']['general']['VolatilityBot_Home']
    
def _run(filename,f_sample_id):
  init()  
  print "[*] Performing static analysis for %s" % (filename)
  try:
      pe =  pefile.PE(filename)
      #/usr/bin/pedump
      return  pe.dump_info()
  except:
      return "error"
  
  
  
  """   
  if __name__ == '__main__':
  #filename = '/Users/Martin/Malware/Dyre/1202/7ba1e8ed2c2e2947799c1076f9614d6b6b090d8d5f95d456317955c9bdad6296'
  filename = '/Users/Martin/Dropbox/Projects/VolatilityBot/V2/Store/ebf8570dfc744a3a1b14cc2b04f2cd2c4c5271403a42bdd77b8b743be27d89c4/RH43H4/injected/svchost.exe.0x820b8c18.0xf40000.fixed_bin'
  _run(filename,1)
  """
