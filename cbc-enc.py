#!/usr/bin/env python3

import binascii
import os
from Crypto.Cipher import AES
import cryptoLib
import argparse



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

    with open(args.i, 'r') as ifile:
        message = ifile.read().replace('\n', '')

    if args.v != None:
        ivfile = open(args.v)
        iv = ivfile.readline()
        iv = iv.rstrip('\n')
    else:
        iv = cryptoLib.genIV()
    
    blocks = cryptoLib.cbc_encrypt(message,iv,key)

    #for i in blocks:
     #   print(i)
if __name__ == "__main__":
     main()


