#!/usr/bin/env python3

import binascii
import os
from Crypto.Cipher import AES
import operator

def hexify(message):
    return binascii.hexlify(bytearray(message)).decode('utf-8')

def dehexify(hext):
    text = binascii.unhexlify(hext)
    return text.decode('utf-8')

def xorify(block, iv):
    result = "%x" % (int(block.encode('hex'), 16) ^ int(iv.encode('hex'),16))
    return result.strip().decode('hex')

def genIV():
    return os.urandom(16) 

def blockify(message):
    blocks = []
    while message:
        blocks.append(message[:16])
        message = message[16:]
    return blocks

def deblockify(blocks):
    message = ""
    for i in blocks:
        message += i
    return message

def padify(blocks):
    need = 0
    padding = 0
    for i in blocks:
        if len(i) < 16:
            tot = 16 - len(i)
            need = 1
    if need == 0:
        pad = chr(16) * 16 
        blocks.append(pad)
        return blocks
    elif need == 1:
        pad = chr(tot) * tot
        blocks[-1] = blocks[-1] + pad
        return blocks

def depadify(blocks):
    last = blocks[-1]
    bytei = last[-2:]
    byte = ord(last[-2])
    if byte == 16:
        blocks = blocks[:-1]
        return blocks    
    else:
        trim = byte
        blocks[-1] = last[:-trim]
        return blocks


def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.
        
    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return  binascii.hexlify(bytearray(ciphertext)).decode('utf-8')
    
def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    enc = binascii.unhexlify(enc)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc.decode('utf-8')

def cbc_encrypt(message,iv,key):
    ciblocks = []
    ciblocks.append(iv)
    newiv = iv
    bitmess = hexify(message)
    blocks = blockify(bitmess)
    blocks = padify(blocks)
    for block in blocks:
        block = block.decode('hex')
        ciblock = xorify(block,newiv)
        print(ciblock)
        ciblock = hexify(ciblock)
        print(ciblock)
        ciphertext = encrypt(key,ciblock)
        ciblocks.append(ciphertext)
        newiv = ciphertext.decode('hex')
    return ciblocks

def test1():
    message = b'when pizzas on a'
    
    key = b'Sixteen byte key'
    iv = genIV()
    
    res = xorify(message,iv)
    
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(res)
    result = binascii.hexlify(bytearray(ciphertext)).decode('utf-8')
    
    enc = binascii.unhexlify(result)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
   
    mess = xorify(enc,iv)
   
    print(mess)

#test1()
    
def test2():

    message = b'when pizzas on a bagel you can eat pizza anytime!!'
    blocks = blockify(message)

    for i in blocks:
        print(i)    
    blocks = padify(blocks)
    
    for i in blocks:
        print(len(i))
    
    blocks = depadify(blocks)
    for i in blocks:
        print(i)
        print(len(i))
test2()
