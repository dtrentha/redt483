#!/usr/bin/env python3

import binascii


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
    


message = "hello my name is david"
message2= "nowwfwutnddgsesgdgvsdk"

new1 = bitify(message)
new2 = bitify(message2)

print(new1)
print(new2)
new3 = xorify(new1,new2)
print(new3)

new4 = xorify(new3,new2)

print(new4)

