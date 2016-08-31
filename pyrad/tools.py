# tools.py
#
# Utility functions
from netaddr import IPAddress
from netaddr import IPNetwork
import struct
import six
import binascii


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

    if str.startswith(b'0x'):
        hexstring = str.split(b'0x')[1]
        return binascii.unhexlify(hexstring)
    else:
        return str


def EncodeAddress(addr):
    if not isinstance(addr, six.string_types):
        raise TypeError('Address has to be a string')
    return IPAddress(addr).packed


def EncodeIPv6Prefix(addr):
    if not isinstance(addr, six.string_types):
        raise TypeError('IPv6 Prefix has to be a string')
    ip = IPNetwork(addr)
    return struct.pack('2B', *[0, ip.prefixlen]) + ip.ip.packed


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
        'family':       b'\x01',
        'action':       b'\x00',
        'direction':    b'\x01',
        'src':          b'\x00\x00\x00\x00',
        'dst':          b'\x00\x00\x00\x00',
        'srcl':         b'\x00',
        'dstl':         b'\x00',
        'proto':        b'\x00',
        'sport':        b'\x00\x00',
        'dport':        b'\x00\x00',
        'sportq':       b'\x00',
        'dportq':       b'\x00'
    }

    for t in str.split(' '):
        key, value = t.split('=')
        if key == 'family' and value == 'ipv6':
            terms[key] = b'\x03'
            if terms['src'] == b'\x00\x00\x00\x00':
                terms['src'] = 16 * b'\x00'
            if terms['dst'] == b'\x00\x00\x00\x00':
                terms['dst'] = 16 * b'\x00'
        elif key == 'action' and value == 'accept':
            terms[key] = b'\x01'
        elif key == 'direction' and value == 'out':
            terms[key] = b'\x00'
        elif key == 'src' or key == 'dst':
            ip = IPNetwork(value)
            terms[key] = ip.ip.packed
            terms[key+'l'] = struct.pack('B', ip.prefixlen)
        elif key == 'sport' or key == 'dport':
            terms[key] = struct.pack('!H', int(value))
        elif key == 'sportq' or key == 'dportq' or key == 'proto':
            terms[key] = struct.pack('B', int(value))

    trailer = 8 * b'\x00'
    result = b'%s%s%s\x00%s%s%s%s%s\x00%s%s%s%s\x00\x00%s' % (
        terms['family'], terms['action'], terms['direction'], terms['src'],
        terms['dst'], terms['srcl'], terms['dstl'], terms['proto'],
        terms['sport'], terms['dport'], terms['sportq'], terms['dportq'],
        trailer)
    return result


def EncodeInteger(num, format='!I'):
    try:
        num = int(num)
    except:
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack(format, num)


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
    addr = addr + b'\x00' * (18-len(addr))
    _, length, prefix = ':'.join(map('{:x}'.format, struct.unpack('!BB'+'H'*8, addr))).split(":", 2)
    return str(IPNetwork("%s/%s" % (prefix, int(length, 16))))


def DecodeIPv6Address(addr):
    addr = addr + b'\x00' * (16-len(addr))
    prefix = ':'.join(map('{:x}'.format, struct.unpack('!'+'H'*8, addr)))
    return str(IPAddress(prefix))


def DecodeAscendBinary(str):
    return str


def DecodeInteger(num, format='!I'):
    return (struct.unpack(format, num))[0]


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
    elif datatype == 'signed':
        return EncodeInteger(value, '!i')
    elif datatype == 'short':
        return EncodeInteger(value, '!H')
    elif datatype == 'byte':
        return EncodeInteger(value, '!B')
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
    elif datatype == 'abinary':
        return DecodeAscendBinary(value)
    elif datatype == 'signed':
        return DecodeInteger(value, '!i')
    elif datatype == 'short':
        return DecodeInteger(value, '!H')
    elif datatype == 'byte':
        return DecodeInteger(value, '!B')
    elif datatype == 'date':
        return DecodeDate(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)
