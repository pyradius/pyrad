# tools.py
#
# Utility functions
import struct
import six
from netaddr import *


def EncodeString(str):
    if len(str) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    if isinstance(str, six.text_type):
        return str.encode('utf-8')
    else:
        return str


def EncodeOctets(str):
    if len(str) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    return str


def EncodeAddress(addr):
    if not isinstance(addr, six.string_types):
        raise TypeError('Address has to be a string')
    return IPAddress(addr).packed


def EncodeIPv6Prefix(addr):
    if not isinstance(addr, six.string_types):
        raise TypeError('IPv6 Prefix has to be a string')
    ip = IPNetwork(addr)
    return struct.pack('2B', *[0, ip.prefixlen ]) + ip.ip.packed


def EncodeIPv6Address(addr):
    if not isinstance(addr, six.string_types):
        raise TypeError('IPv6 Address has to be a string')
    return IPAddress(addr).packed


def EncodeInteger(num):
    if not isinstance(num, six.integer_types):
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack('!I', num)


def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError('Can not encode non-integer as date')
    return struct.pack('!I', num)


def DecodeString(str):
    try:
        return str.decode('utf-8')
    except:
        return str

def DecodeOctets(str):
    return str


def DecodeAddress(addr):
    return '.'.join(map(str, struct.unpack('BBBB', addr)))


def DecodeIPv6Prefix(addr):
    addr = addr + '\x00' * (18-len(addr))
    _, length, prefix = ':'.join(map('{:x}'.format, \
        struct.unpack('!BB'+'H'*8, addr))).split(":", 2)
    return str(IPNetwork("%s/%s" % (prefix, int(length, 16))))


def DecodeIPv6Address(addr):
    addr = addr + '\x00' * (16-len(addr))
    prefix = ':'.join(map('{:x}'.format, struct.unpack('!'+'H'*8, addr)))
    return str(IPAddress(prefix)


def DecodeInteger(num):
    return (struct.unpack('!I', num))[0]


def DecodeDate(num):
    return (struct.unpack('!I', num))[0]


def EncodeAttr(datatype, value):
    if datatype == 'string':
        return EncodeString(value)
    elif datatype == 'octets':
        return EncodeOctets(value)
    elif datatype == 'integer':
        return EncodeInteger(value)
    elif datatype == 'ipaddr':
        return EncodeAddress(value)
    elif datatype == 'ipv6prefix':
        return EncodeIPv6Prefix(value)
    elif datatype == 'ipv6addr':
        return EncodeIPv6Address(value)
    elif datatype == 'date':
        return EncodeDate(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)


def DecodeAttr(datatype, value):
    if datatype == 'string':
        return DecodeString(value)
    elif datatype == 'octets':
        return DecodeOctets(value)
    elif datatype == 'integer':
        return DecodeInteger(value)
    elif datatype == 'ipaddr':
        return DecodeAddress(value)
    elif datatype == 'ipv6prefix':
        return DecodeIPv6Prefix(value)
    elif datatype == 'ipv6addr':
        return DecodeIPv6Address(value)
    elif datatype == 'date':
        return DecodeDate(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)
