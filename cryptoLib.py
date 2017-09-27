#!/usr/bin/env python3

import binascii
import os


def bitify(message, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(message.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def debitify(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    hexs = '%x' % n
    i = len(hexs)
    binary = binascii.unhexlify(hexs.zfill(i + (i & 1)))
    return binary.decode(encoding, errors)
        
def xorify(block, iv):
    return '{0:b}'.format(int(block,2) ^ int(iv,2))
    
def genIV():
    iv = binascii.hexlify(os.urandom(8))
    return bitify(iv)

def blockify(message):
    blocks = []
    while message:
        blocks.append(message[:128])
        message = message[128:]
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
        if len(i) < 128:
            tot = 128 - len(i)
            tot = tot / 8
            padding = tot
            need = 1
    if need == 0:
        pad = '{0:08b}'.format(16)
        pad *= 16
        blocks.append(pad)
        return blocks
    elif need == 1:
        pad = '{0:08b}'.format(padding)
        pad *= padding
        blocks[-1] = blocks[-1] + pad
        return blocks

def depadify(blocks):
    last = blocks[-1]
    bits = last[-8:]
    byte = int(bits,2)
    #print(byte) 
    if byte == 16:
        blocks = blocks[:-1]
        return blocks    
    else:
        trim = byte * 8
        blocks[-1] = last[:-trim]
        return blocks


message1 = "when pizzas on a bagel you can eat pizza anytime"

message2 = "abcafdsgdsgdsgdsa"

mess = bitify(message2)
blocks = blockify(mess)
blocks = padify(blocks)
blocks = depadify(blocks)

mess = deblockify(blocks)

mess = debitify(mess)
print(mess)


