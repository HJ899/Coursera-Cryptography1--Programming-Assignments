#!/usr/bin/env python
# coding: utf-8

from Crypto.Cipher import AES
from math import ceil

keys_cbc = ['140b41b22a29beb4061bda66b6747e14', '140b41b22a29beb4061bda66b6747e14']
cyps_cbc = ['4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
           '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253']
keys_ctr = ['36f18357be4dbd77f050515c73fcf9f2', '36f18357be4dbd77f050515c73fcf9f2']
cyps_ctr = ['69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
           '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451']

def decryptCBC(key, cyp):
	key = bytes.fromhex(key)
	cyp = bytes.fromhex(cyp)
	cipher = AES.new(key, AES.MODE_ECB)
	currentIV = cyp[0:16]
	toDecrypt = cyp[16:]
	final = bytes()
	for ix in range(len(toDecrypt)//16):
		c_i = toDecrypt[ix * 16: (ix + 1) * 16]
		d_i = cipher.decrypt(c_i)
		final = final + bytes(x ^ y for x,y in zip(d_i, currentIV))
		currentIV = c_i
	return final[0 : -final[-1]].decode('utf-8')

def decryptCTR(key, cyp):
	key = bytes.fromhex(key)
	cyp = bytes.fromhex(cyp)
	cipher = AES.new(key, AES.MODE_ECB)
	IV = int.from_bytes(cyp[0:16], byteorder = 'big')
	toDecrypt = cyp[16:]
	final = bytes()
	k = int(ceil(len(toDecrypt)/16))
	for ix in range(k):
		currentIV = (IV + ix).to_bytes(16, 'big')
		f_i = cipher.encrypt(currentIV)
		c_i = toDecrypt[ix * 16 : min((ix + 1) * 16, len(toDecrypt))]
		t = min(len(f_i), len(c_i))
		final = final + bytes(x ^ y for x,y in zip(f_i[0 : t], c_i[0 : t]))
	return final.decode('utf-8')

for key, cyp in zip(keys_cbc, cyps_cbc): print(decryptCBC(key, cyp))
for key, cyp in zip(keys_ctr, cyps_ctr): print(decryptCTR(key, cyp))

