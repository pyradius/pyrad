# tools.py
#
# Utility functions
from netaddr import IPAddress
from netaddr import IPNetwork
import struct
import six
import binascii


def encode_string(str):
  if len(str) > 253:
    raise ValueError('Can only encode strings of <= 253 characters')
  if isinstance(str, six.text_type):
    return str.encode('utf-8')
  else:
    return str


def encode_octets(str):
  if len(str) > 253:
    raise ValueError('Can only encode strings of <= 253 characters')

  if str.startswith(b'0x'):
    hexstring = str.split(b'0x')[1]
    return binascii.unhexlify(hexstring)
  else:
    return str


def encode_address(addr):
  if not isinstance(addr, six.string_types):
    raise TypeError('Address has to be a string')
  return IPAddress(addr).packed


def encode_ipv6_prefix(addr):
  if not isinstance(addr, six.string_types):
    raise TypeError('IPv6 Prefix has to be a string')
  ip = IPNetwork(addr)
  return struct.pack('2B', *[0, ip.prefixlen]) + ip.ip.packed


def encode_ipv6_address(addr):
  if not isinstance(addr, six.string_types):
    raise TypeError('IPv6 Address has to be a string')
  return IPAddress(addr).packed


def encode_ascend_binary(str):
  """
  Format: List of type=value pairs sperated by spaces.

  Example: 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'

  Type:
   family  ipv4(default) or ipv6
   action  discard(default) or accept
   direction in(default) or out
   src   source prefix (default ignore)
   dst   destination prefix (default ignore)
   proto  protocol number / next-header number (default ignore)
   sport  source port (default ignore)
   dport  destination port (default ignore)
   sportq  source port qualifier (default 0)
   dportq  destination port qualifier (default 0)

  Source/Destination Port Qualifier:
   0 no compare
   1 less than
   2 equal to
   3 greater than
   4 not equal to
  """

  terms = {
    'family': b'\x01',
    'action': b'\x00',
    'direction': b'\x01',
    'src': b'\x00\x00\x00\x00',
    'dst': b'\x00\x00\x00\x00',
    'srcl': b'\x00',
    'dstl': b'\x00',
    'proto': b'\x00',
    'sport': b'\x00\x00',
    'dport': b'\x00\x00',
    'sportq': b'\x00',
    'dportq': b'\x00'
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
      terms[key + 'l'] = struct.pack('B', ip.prefixlen)
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


def encode_integer(num, fmt='!I'):
  try:
    num = int(num)
  except:
    raise TypeError('Can not encode non-integer as integer')
  return struct.pack(fmt, num)


def encode_date(num):
  if not isinstance(num, int):
    raise TypeError('Can not encode non-integer as date')
  return struct.pack('!I', num)


def decode_string(str):
  try:
    return str.decode('utf-8')
  except:
    return str


def decode_octets(str):
  return str


def decode_address(addr):
  return '.'.join([str(x) for x in struct.unpack('BBBB', addr)])


def decode_ipv6_prefix(addr):
  addr = addr + b'\x00' * (18 - len(addr))
  _, length, prefix = ':'.join(
    map('{:x}'.format, struct.unpack('!BB' + 'H' * 8, addr))).split(":", 2)
  return str(IPNetwork("%s/%s" % (prefix, int(length, 16))))


def decode_ipv6_address(addr):
  addr = addr + b'\x00' * (16 - len(addr))
  prefix = ':'.join(map('{:x}'.format, struct.unpack('!' + 'H' * 8, addr)))
  return str(IPAddress(prefix))


def decode_ascend_binary(str):
  return str


def decode_integer(num, fmt='!I'):
  return (struct.unpack(fmt, num))[0]


def decode_date(num):
  return (struct.unpack('!I', num))[0]


def encode_attr(datatype, value):
  if datatype == 'string':
    return encode_string(value)
  elif datatype == 'octets':
    return encode_octets(value)
  elif datatype == 'integer':
    return encode_integer(value)
  elif datatype == 'ipaddr':
    return encode_address(value)
  elif datatype == 'ipv6prefix':
    return encode_ipv6_prefix(value)
  elif datatype == 'ipv6addr':
    return encode_ipv6_address(value)
  elif datatype == 'abinary':
    return encode_ascend_binary(value)
  elif datatype == 'signed':
    return encode_integer(value, '!i')
  elif datatype == 'short':
    return encode_integer(value, '!H')
  elif datatype == 'byte':
    return encode_integer(value, '!B')
  elif datatype == 'date':
    return encode_date(value)
  else:
    raise ValueError('Unknown attribute type %s' % datatype)


def decode_attr(datatype, value):
  if datatype == 'string':
    return decode_string(value)
  elif datatype == 'octets':
    return decode_octets(value)
  elif datatype == 'integer':
    return decode_integer(value)
  elif datatype == 'ipaddr':
    return decode_address(value)
  elif datatype == 'ipv6prefix':
    return decode_ipv6_prefix(value)
  elif datatype == 'ipv6addr':
    return decode_ipv6_address(value)
  elif datatype == 'abinary':
    return decode_ascend_binary(value)
  elif datatype == 'signed':
    return decode_integer(value, '!i')
  elif datatype == 'short':
    return decode_integer(value, '!H')
  elif datatype == 'byte':
    return decode_integer(value, '!B')
  elif datatype == 'date':
    return decode_date(value)
  else:
    raise ValueError('Unknown attribute type %s' % datatype)
