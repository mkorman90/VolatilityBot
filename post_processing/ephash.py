#!/usr/bin/python
 
import pefile
import pydasm
import os
import hashlib
import re
import shutil
import argparse
import json
import sys
 
 
"""
TODO: argparse
    for now:
        python RetrieveEPcode.py Samples/ 12    sha1         gen              build_clusters    zbot_12_gen
                                  dir    bytes  algorithm   generalization   make_directories?  dirname
 
 
"""
bytes_to_read = 64 
READ_OFFSET = 0 
 
def pe_read_x_bytes_from_ep(pepath):


         
    try:
        pe =  pefile.PE(pepath)
         
        print "EP of %s is %s" % (pepath,pe.OPTIONAL_HEADER.AddressOfEntryPoint)        
         
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_memory_mapped_image()[ep+READ_OFFSET:ep+READ_OFFSET+int(bytes_to_read)]
        offset = 0
        disasm_data = ""
        ret_assembly = ""
        while offset < len(data):
          i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
          if (i == None):
            print "We are done here."
            break
           
     
          #Strip stuff that can change from sample to sample, like constants or offets... (Replace with *)
          diasm_curr_string = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
          #print diasm_curr_string
     
                    
          line = diasm_curr_string
          ret_assembly = ret_assembly + diasm_curr_string + "/"
          line = generalize(line,)
               
          offset += i.length
          #disasm_data = disasm_data + str(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset))  
         
          disasm_data = disasm_data + line
         
        #print disasm_data         
        hash_object = hashlib.sha224(disasm_data)
        retval_i = hash_object.hexdigest()
        return (retval_i)
         
    except:
        #print 'An exception occurred, value:', e.value
        return ("failed")   
 
#Assembly generalization - In the future will generalize more instructions i.e: (mov eax,0) = (xor eax eax) 
def generalize(line):
  processed_line = re.sub(r"(eax|ebx|ecx|edx|edi|esi)","reg",line)
  processed_line = re.sub(r"0x[a-f0-9]{1,8}","hexval",processed_line)
   
  #Lots of ways to zero a register =]
  processed_line = re.sub(r"xor reg,reg","zero reg",processed_line)
  processed_line = re.sub(r"mov reg,0","zero reg",processed_line)
  processed_line = re.sub(r"and reg,0","zero reg",processed_line)
  processed_line = re.sub(r"mul reg,0","zero reg",processed_line)
  processed_line = re.sub(r"sub reg,reg","zero reg",processed_line)
  processed_line = re.sub(r"lea reg,[0]","zero reg",processed_line)
   
  #increase one
  processed_line = re.sub(r"inc reg","+1 reg",processed_line)
  processed_line = re.sub(r"add reg,1","+1 reg",processed_line)
   
  #decrease one
  processed_line = re.sub(r"sub reg","-1 reg",processed_line)
  processed_line = re.sub(r"sub reg,1","-1 reg",processed_line)
   
   
  return processed_line     

def calc_ephash(filename):
    retval = pe_read_x_bytes_from_ep(filename)
    print "[*] Hash of " + str(bytes_to_read) + " Bytes at EP of: " + str(filename) + " : " + retval
    print "[*] ====================================="   
    return retval          
       
def calc_imphash(filename):
    try:    
        pe =  pefile.PE(filename)
        ret_imphash = pe.get_imphash()
        return ret_imphash
    except:
        return 'failed'
       
def main():                  
    fname = sys.argv[1]                  
    ephash_result = calc_ephash(fname) 
    imphash_result = calc_imphash(fname)        

    print 'ephash %s imphash %s' % (ephash_result,imphash_result)    

                 
if __name__ == '__main__':
    main()      