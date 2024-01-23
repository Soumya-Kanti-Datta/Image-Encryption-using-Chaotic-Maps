#!/usr/bin/env python
import binascii
pic = "peakpx.jpg"
with open(pic , 'rb') as p:
	hexa_data = p.read()
print(binascii.hexlify(hexa_data)) 