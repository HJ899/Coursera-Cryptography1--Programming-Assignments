#!/usr/bin/env python
# coding: utf-8
import urllib.request as request
import urllib.error as error
import sys
from tqdm import tqdm
TARGET = 'http://crypto-class.appspot.com/po?er='
CIPHER = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
	def query(self, q):
		req = request.Request(TARGET + q) # Send HTTP request to server
		try:
			f = request.urlopen(req) # Wait for response
		except error.HTTPError as e:          
			#print("We got: %d"% e.code)       # Print response code
			if e.code == 404:
				return True # good padding
			return False # bad padding

	def requestAndDecrypt(self, IV, CYP): # One Block CBC decryption mechanism by using IV and CYPHER
		final = list() #Final list of bytes
		for byteNo in tqdm(range(1,17)):
			tempIV = list(IV)
			for t in range(byteNo - 1):
				tempIV[-(t+1)] ^= byteNo ^ final[t] 
			tempIV[-byteNo] ^= byteNo
			for g in range(128):
				G = 127 - g
				tempIV[-byteNo] ^= G ^ ( 0 if G == 127 else G+1 )
				reqCYP = bytes(tempIV).hex() + CYP.hex()
				if self.query(reqCYP) == True: # Issue HTTP query with the argument
					final.append(G) # add byte to final list
					break
		final.reverse() # reverse the list
		return bytes(final) # return list in byte format

	def decrypt(self, cypherText): # Must be HEX encoded
		cypherTextBts = bytes.fromhex(cypherText) # Convert cypherText to bytes
		finalAns = bytes()
		for ix in range(1, len(cypherTextBts)//16): # Loop over all blocks to decrypt
			print("\nBLOCK NO : %d/%d"%(ix, len(cypherTextBts)//16 - 1))
			lastBlock = cypherTextBts[(ix - 1)*16 : ix * 16]
			currentBlock = cypherTextBts[ix * 16 : (ix + 1) * 16]
			finalAns = finalAns + self.requestAndDecrypt(lastBlock, currentBlock) # Feed last block as IV and Current block as CYPHER
		return finalAns.decode('utf-8')

if __name__ == "__main__":
	po = PaddingOracle()
	msg = po.decrypt(CIPHER)
	print("\n" + msg)