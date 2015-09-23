# -*- coding: utf-8 -*-
"""
Created on Mon Jan 19 21:53:42 2015

@author: martin
"""

import socket
import sys
import subprocess
 
s = socket.socket()
s.bind(("192.168.47.20",9999))
s.listen(1) # Acepta hasta 10 conexiones entrantes.
sc, address = s.accept()
 
print address
i=1
f = open('c:\\binary_to_exec.exe','wb')
i=i+1
 
 
l = sc.recv(1024)
while (l):
    f.write(l)
    l = sc.recv(1024)
f.close()
 
 
sc.close()
s.close()
 
#Execute the file
subprocess.call(['C:\\Documents and Settings\\ducky\\Desktop\\testing.exe'])
