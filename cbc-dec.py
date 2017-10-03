#!/usr/bin/env python3

import binascii
import os
from Crypto.Cipher import AES
import cryptoLib
import argparse
import pickle


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-k')
    parser.add_argument('-i')
    parser.add_argument('-o')
    parser.add_argument('-v', nargs ='?')

    args = parser.parse_args()

    kfile = open(args.k)
    key = kfile.readline()
    key = key.rstrip('\n')

    blocks = []

    ifile = open(args.i, 'r')
    blocks = ifile.readlines()

    for i in range(len(blocks)):
        blocks[i] = blocks[i].strip('\n') 

    output = open(args.o, 'w')

    if args.v != None:
        ivfile = open(args.v)
        iv = ivfile.readline()
        iv = iv.rstrip('\n')
        iv = iv.decode('hex')
    else:
        iv = cryptoLib.genIV()

    message = cryptoLib.cbc_dec(blocks,key)
        

    output.write(message)

if __name__ == "__main__":
     main()



