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

def padify(blocks):
    for i in blocks:
        if len(i) < 128:
            tot = 128 - len(i)
            tot = tot / 16
            string = ("0" + str(tot)) * tot
            newstr = bitify(string)
            i += newstr
            print(i)
            return blocks
    pad = bitify("0808080808080808")
    blocks.append(pad)
    return blocks


message1 = "hello my baby hello my darling hello my rag time gal when pizzas on a bagel you can eat pizza anytime"

message2 = "abcafdsgdsgdsgdsa"

newmess = bitify(message1)

blocks = blockify(newmess)

blocks = padify(blocks)

for i in blocks:
     print(i)





