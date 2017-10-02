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
    return result.decode('hex')

def genIV():
    return os.urandom(8) 

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
            tot = tot / 2
            padding = tot
            need = 1
    if need == 0:
        pad = binascii.hexlify("8") 
        pad *= 8
        blocks.append(pad)
        return blocks
    elif need == 1:
        pad = binascii.hexlify(str(padding))
        pad *= padding
        blocks[-1] = blocks[-1] + pad
        return blocks

def depadify(blocks):
    last = blocks[-1]
    hext = last[-2:]
    byte = int(hext.decode('hex'))
    if byte == 16:
        blocks = blocks[:-1]
        return blocks    
    else:
        trim = byte * 2
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
    message = "when pizzas on a bagel you can eat pizza anytime!"

    message = hexify(message)

    blocks = blockify(message)
    blocks = padify(blocks)

    for i in blocks:
        print(i)
    print('')
    blocks = depadify(blocks)

    for i in blocks:
        print(i)

    messagenow = deblockify(blocks)

    print(messagenow)
    messagenow = dehexify(messagenow)
    print(messagenow)

#test1()

def test2():
    message = "thisisit"
    iv = genIV()
    print(message)
    print(iv)
    iv = iv.decode('hex')
    result = xorify(message,iv)
    print(result)
    result = xorify(result,iv)
    print(result) 
#test2()
