#!/usr/bin/env python
# coding: utf-8
import gmpy2
from tqdm import tqdm

p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333
B = 2**20

hashT = {}
gx = 1
print("\nBuilding Hash Table\n")
for i in tqdm(range(B+1)):
    gx_inv = int(gmpy2.powmod(gx, -1, p))
    h_by_gx = (gx_inv*h)%p
    hashT[h_by_gx] = int(i)
    gx =(gx * g)%p

print("\nSearching for Value\n")
gb = int(gmpy2.powmod(g, B, p))
curr = 1
x0,x1 = None,None
for j in tqdm(range(B+1)):
    if curr in hashT:
        x0 = j
        x1 = hashT[curr]
        break
    curr = (curr*gb)%p

x = x0 * B + x1
print("Ans : %d"%x)





