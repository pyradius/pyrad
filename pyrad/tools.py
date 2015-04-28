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


def EncodeAscendBinary(str):
    """
    Format: List of type=value pairs sperated by spaces.

    Example: 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'

    Type:
        family      ipv4(default) or ipv6
        action      discard(default) or accept
        direction   in(default) or out
        src         source prefix (default ignore)
        dst         destination prefix (default ignore)
        proto       protocol number / next-header number (default ignore)
        sport       source port (default ignore)
        dport       destination port (default ignore)
        sportq      source port qualifier (default 0)
        dportq      destination port qualifier (default 0)

    Source/Destination Port Qualifier:
        0   no compare
        1   less than
        2   equal to
        3   greater than
        4   not equal to
    """

    terms = {
        'family'    : '\x01',
        'action'    : '\x00',
        'direction' : '\x00',
        'src'       : '\x00\x00\x00\x00',
        'dst'       : '\x00\x00\x00\x00',
        'srcl'      : '\x00',
        'dstl'      : '\x00',
        'proto'     : '\x00',
        'sport'     : '\x00\x00',
        'dport'     : '\x00\x00',
        'sportq'    : '\x00',
        'dportq'    : '\x00'
    }


    for t in str.split(' '):
        key, value = t.split('=')
        if key == 'family' and value == 'ipv6':
            terms[key] = '\x03'
            if terms['src'] == '\x00\x00\x00\x00':
                terms['src'] == 16 * '\x00'
            if terms['dst'] == '\x00\x00\x00\x00':
                terms['dst'] == 16 * '\x00'
        elif key == 'action' and value == 'accept':
            terms[key] = '\x01'
        elif key == 'direction' and value == 'in':
            terms[key] = '\x01'
        elif key == 'src' or key == 'dst':
            ip = IPNetwork(value)
            terms[key] = ip.ip.packed
            terms[key+'l'] = struct.pack('B', ip.prefixlen)
        elif key == 'sport' or key == 'dport':
            terms[key] = struct.pack('!H', int(value))
        elif key == 'sportq' or key == 'dportq' or key == 'proto':
            terms[key] = struct.pack('B', int(value))

    return '%s%s%s\x00%s%s%s%s%s\x00%s%s%s%s\x00\x00%s' % (terms['family'], \
        terms['action'], terms['direction'], terms['src'], terms['dst'], \
        terms['srcl'], terms['dstl'], terms['proto'], terms['sport'], \
        terms['dport'], terms['sportq'], terms['dportq'], 8 * '\x00')


def EncodeInteger(num):
    if not isinstance(num, six.integer_types):
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack('!I', num)


def EncodeShort(num):
    return struct.pack('!H', int(num))


def EncodeByte(num):
    return struct.pack('!B', int(num))


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
    return str(IPAddress(prefix))


def DecodeAscendBinary(str):
    return str


def DecodeInteger(num):
    return (struct.unpack('!I', num))[0]


def DecodeShort(num):
    return (struct.unpack('!H', num))[0]


def DecodeByte(num):
    return (struct.unpack('!B', num))[0]


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
    elif datatype == 'abinary':
        return EncodeAscendBinary(value)
    elif datatype == 'short':
        return EncodeShort(value)
    elif datatype == 'byte':
        return EncodeByte(value)
    elif datatype == 'date':
        return EncodeDate(value)
    else:
        # encode unknown as string
        # alternate # raise ValueError('Unknown attribute type %s' % datatype)
        return EncodeString(value)


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
    elif datatype == 'abinary':
        return DecodeAscendBinary(value)
    elif datatype == 'short':
        return DecodeShort(value)
    elif datatype == 'byte':
        return DecodeByte(value)
    elif datatype == 'date':
        return DecodeDate(value)
    else:
        # decode unknown as string
        # alternate # raise ValueError('Unknown attribute type %s' % datatype)
        return DecodeString(value)
