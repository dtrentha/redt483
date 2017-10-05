#!/usr/bin/env python3

import binascii
import os
import sys
import argparse
from Crypto.Cipher import AES


def hexify(message):
    return binascii.hexlify(bytearray(message)).decode('utf-8')

def dehexify(hext):
    text = binascii.unhexlify(hext)
    return text.decode('utf-8')

#XOR two raw byte strings
def xorify(block, iv):
    result = "%x" % (int(block.encode('hex'), 16) ^ int(iv.encode('hex'),16))
    result = format(result,'0>32')
    result = result.strip().decode('hex')
    return result

#Generate an IV in raw bytes
def genIV():
    return os.urandom(16) 

#Takes a message of plain text and breaks it into blocks of 128 bits.
def blockify(message):
    blocks = []
    while message:
        blocks.append(message[:16])
        message = message[16:]
    return blocks

#Takes blocks of 128 bits and turns it into a single string.
def deblockify(blocks):
    message = ""
    for i in blocks:
        message += i
    return message

#Pads the blocks of the message with int converted into chars.
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

#Takes off the padding.
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
    return enc

def cbc_enc(message,iv,key):
    ciblocks = []
    ciblocks.append(hexify(iv))
    newiv = iv
    blocks = blockify(message)
    blocks = padify(blocks)
    for i in blocks:
        ciblock = xorify(i,newiv)
        ciphertext = encrypt(key,ciblock)
        ciblocks.append(ciphertext)
        ciphertext = binascii.unhexlify(ciphertext)
        newiv = ciphertext
    return ciblocks

def cbc_dec(ciblocks,key):
    dec = []
    ciblocks.reverse()
    num = len(ciblocks)
    for i in range(num - 1):
        hext = ciblocks[0]
        iv = binascii.unhexlify(ciblocks[1])
        decblock = decrypt(key, hext)
        decblock = xorify(decblock,iv)
        dec.insert(0, decblock)
        del ciblocks[0] 
    dec = depadify(dec)
    message = deblockify(dec)
    return message

def main():
    blocks = []

    mode = sys.argv[1]
    parser = argparse.ArgumentParser()
    parser.add_argument('-k')
    parser.add_argument('-i')
    parser.add_argument('-o')
    parser.add_argument('-v', nargs ='?')

    args = parser.parse_args()

    kfile = open(args.k)
    key = kfile.readline()
    key = key.rstrip('\n')

    ifile = open(args.i, 'r')
    blocks = ifile.readlines()

    output = open(args.o, 'w')

    if args.v != None:
        ivfile = open(args.v)
        iv = ivfile.readline()
        iv = iv.rstrip('\n')
        iv = iv.decode('hex')
    else:
        iv = cryptoLib.genIV()

    
    if mode == "cbc-enc":
        
        message = ifile.read().replace('\n', '')
        blocks = cbc_enc(message,iv,key)
        
        for i in blocks:
            output.write("%s\n" % i)

    elif mode == "cbc-dec":
        
        blocks = ifile.readlines()
        message = cbc_dec(blocks, key)
        output.write(message)

    elif mode == "ctr-enc"
        
        message = ifile.read().replace('\n', '')
        blocks = ctr_enc(message,iv,key)
     
        for i in blocks:
            output.write("%s\n" % i)

    elif mode == "ctr-dec":
        
        blocks = ifile.readlines()
        message = ctr_dec(blocks,key)
        output.write(message)

    else:
        print("not a valid mode")
        

if __name__ == "__main__":
     main()

