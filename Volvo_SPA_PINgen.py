# Come visit us as https://v-spa.net #

from ctypes import *
from time import gmtime, strftime   
import struct
import sys


sampleseed = "39 0a 58"
samplekey = "f6 4c 2f"
start = 0x0000000000  # hex literal, gives us a regular integer
end = 0xFFFFFFFFFF
realkey = (int(samplekey[0:2],16)<<16) + (int(samplekey[3:5],16)<<8) + (int(samplekey[6:8],16))
realseed = sampleseed

def key_from_seed(seed, secret):

       
    s1 = int(secret[0:2],16)
    s2 = int(secret[3:5],16)
    s3 = int(secret[6:8],16)
    s4 = int(secret[9:11],16)
    s5 = int(secret[12:14],16)

    seed_int = (int(seed[0:2],16)<<16) + (int(seed[3:5],16)<<8) + (int(seed[6:8],16)) 
    or_ed_seed = ((seed_int & 0xFF0000) >> 16) | (seed_int & 0xFF00) | (s1 << 24) | (seed_int & 0xff) << 16
    mucked_value = 0xc541a9

    for i in range(0,32):
        a_bit = ((or_ed_seed >> i) & 1 ^ mucked_value & 1) << 23
        v9 = v10 = v8 = a_bit | (mucked_value >> 1);
        mucked_value = v10 & 0xEF6FD7 | ((((v9 & 0x100000) >> 20) ^ ((v8 & 0x800000) >> 23)) << 20) | (((((mucked_value >> 1) & 0x8000) >> 15) ^ ((v8 & 0x800000) >> 23)) << 15) | (((((mucked_value >> 1) & 0x1000) >> 12) ^ ((v8 & 0x800000) >> 23)) << 12) | 32 * ((((mucked_value >> 1) & 0x20) >> 5) ^ ((v8 & 0x800000) >> 23)) | 8 * ((((mucked_value >> 1) & 8) >> 3) ^ ((v8 & 0x800000) >> 23));

    for j in range(0,32):
        a_bit = ((((s5 << 24) | (s4 << 16) | s2 | (s3 << 8)) >> j) & 1 ^ mucked_value & 1) << 23;
        v14 = v13 = v12 = a_bit | (mucked_value >> 1);
        mucked_value = v14 & 0xEF6FD7 | ((((v13 & 0x100000) >> 20) ^ ((v12 & 0x800000) >> 23)) << 20) | (((((mucked_value >> 1) & 0x8000) >> 15) ^ ((v12 & 0x800000) >> 23)) << 15) | (((((mucked_value >> 1) & 0x1000) >> 12) ^ ((v12 & 0x800000) >> 23)) << 12) | 32 * ((((mucked_value >> 1) & 0x20) >> 5) ^ ((v12 & 0x800000) >> 23)) | 8 * ((((mucked_value >> 1) & 8) >> 3) ^ ((v12 & 0x800000) >> 23));

    key = ((mucked_value & 0xF0000) >> 16) | 16 * (mucked_value & 0xF) | ((((mucked_value & 0xF00000) >> 20) | ((mucked_value & 0xF000) >> 8)) << 8) | ((mucked_value & 0xFF0) >> 4 << 16);

    #print ("Computed key: %x" % key)
    #return "%02X %02X %02X" % ( (key & 0xff0000) >> 16, (key & 0xff00) >> 8, key & 0xff)
    return key

for i in reversed(range(start, end + 1)):
    psecret = "%02X %02X %02X %02X %02X" % ( (i & 0xff00000000) >> 32,(i & 0xff000000) >> 24,(i & 0xff0000) >> 16, (i & 0xff00) >> 8, i & 0xff)
    testkey = key_from_seed(realseed, psecret)
    #print (psecret)
    if testkey == realkey:
        print ("Possible PIN Found:") 
        print (psecret)
        print(strftime("%H:%M:%S", gmtime())) 
