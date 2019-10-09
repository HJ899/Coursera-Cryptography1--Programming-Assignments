#!/usr/bin/env python
# coding: utf-8

from Crypto.Hash import SHA256

f = open("6.1.intro.mp4_download", "rb") 
data = f.read()
f.close()

l = len(data)
lft,rt = (l - l%1024, l)
prevHash = b''

while lft > -1:
    currData = data[lft:rt] + prevHash
    h = SHA256.new()
    h.update(currData)
    prevHash = h.digest()
    rt = lft
    lft -= 1024
print(prevHash.hex())
