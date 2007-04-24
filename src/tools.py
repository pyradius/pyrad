# tools.py
#
# Utility functions

import struct


def EncodeString(str):
	assert len(str)<=253

	return str


def EncodeAddress(addr):
	(a,b,c,d)=map(int, addr.split("."))
	return struct.pack("BBBB", a, b, c, d)


def EncodeInteger(num):
	return struct.pack("!I", num)


def EncodeDate(num):
	return struct.pack("!I", num)


def DecodeString(str):
	return str


def DecodeAddress(addr):
	return ".".join(map(str, struct.unpack("BBBB", addr)))


def DecodeInteger(num):
	return (struct.unpack("!I", num))[0]


def DecodeDate(num):
	return (struct.unpack("!I", num))[0]


def EncodeAttr(datatype, value):
	if datatype=="string":
		return EncodeString(value)
	elif datatype=="ipaddr":
		return EncodeAddress(value)
	elif datatype=="integer":
		return EncodeInteger(value)
	elif datatype=="date":
		return EncodeDate(value)
	else:
		return value
	

def DecodeAttr(datatype, value):
	if datatype=="string":
		return DecodeString(value)
	elif datatype=="ipaddr":
		return DecodeAddress(value)
	elif datatype=="integer":
		return DecodeInteger(value)
	elif datatype=="date":
		return DecodeDate(value)
	else:
		return value
	

