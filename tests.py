#!/usr/bin/env python3

import binascii
import os
from Crypto.Cipher import AES
import operator
import cryptoLib

c = cryptoLib

def test1():
    message = b'when pizzas on a'

    key = b'Sixteen byte key'
    iv = c.genIV()

    res = c.xorify(message,iv)

    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(res)
    result = binascii.hexlify(bytearray(ciphertext)).decode('utf-8')

    enc = binascii.unhexlify(result)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)

    mess = c.xorify(enc,iv)

    print(mess)

#test1()

def test2():

    message = b'when pizzas on a bagel you can eat pizza anytime!!'
    blocks = c.blockify(message)

    for i in blocks:
        print(i)
    blocks = c.padify(blocks)

    for i in blocks:
        print(len(i))

    blocks = c.depadify(blocks)
    for i in blocks:
        print(i)
        print(len(i))

#test2()

def test3():

    message = b'The meal was over. The metal traders, after many gestures of gratitude for the venison, withdrew to their camp at the far side of the island. Before he disappeared into the shadows, Tarketios looked over his shoulder and gave Lara a parting grin.While the others settled down to sleep, Larth stayed awake a while longer, as was his habit.'
    iv = c.genIV()
    key = '3132333435363738393061626364656631323334353637383930616263646566'
    key = c.dehexify(key)
    blocks = c.cbc_enc(message,iv,key) 
    print(message)

    message = c.cbc_dec(blocks,key)
    print(message)
   
test3() 
