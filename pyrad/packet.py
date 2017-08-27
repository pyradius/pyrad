# packet.py
#
# Copyright 2002-2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS packet as defined in RFC 2138


import struct
import random
try:
  import hashlib
  MD5Constructor = hashlib.md5
except ImportError:
  # BBB for python 2.4
  import md5
  MD5Constructor = md5.new
import six
from pyrad import tools

# Packet codes
ACCESSREQUEST = 1
ACCESSACCEPT = 2
ACCESSREJECT = 3
ACCOUNTINGREQUEST = 4
ACCOUNTINGRESPONSE = 5
ACCESSCHALLENGE = 11
STATUSSERVER = 12
STATUSCLIENT = 13
DISCONNECTREQUEST = 40
DISCONNECTACK = 41
DISCONNECTNAK = 42
COAREQUEST = 43
COAACK = 44
COANAK = 45

# Use cryptographic-safe random generator as provided by the OS.
RANDOMGENERATOR = random.SystemRandom()

# Current ID
CURRENTID = RANDOMGENERATOR.randrange(1, 255)


class PacketError(Exception):
  pass


class Packet(dict):

  """Packet acts like a standard python map to provide simple access
  to the RADIUS attributes. Since RADIUS allows for repeated
  attributes the value will always be a sequence. pyrad makes sure
  to preserve the ordering when encoding and decoding packets.

  There are two ways to use the map intereface: if attribute
  names are used pyrad take care of en-/decoding data. If
  the attribute type number (or a vendor ID/attribute type
  tuple for vendor attributes) is used you work with the
  raw data.

  Normally you will not use this class directly, but one of the
  :obj:`AuthPacket` or :obj:`AcctPacket` classes.
  """

  def __init__(
    self,
    code=0,
    id=None,
    secret=six.b(''),
    authenticator=None,
      **attributes):
    """Constructor

    :param dict: RADIUS dictionary
    :type dict: pyrad.dictionary.Dictionary class
    :param secret: secret needed to communicate with a RADIUS server
    :type secret: string
    :param id:  packet identifaction number
    :type id:  integer (8 bits)
    :param code: packet type code
    :type code: integer (8bits)
    :param packet: raw packet to decode
    :type packet: string
    """
    dict.__init__(self)
    self.code = code
    if id is not None:
      self.id = id
    else:
      self.id = create_id()
    if not isinstance(secret, six.binary_type):
      raise TypeError('secret must be a binary string')
    self.secret = secret
    if authenticator is not None and \
        not isinstance(authenticator, six.binary_type):
      raise TypeError('authenticator must be a binary string')
    self.authenticator = authenticator

    if 'dict' in attributes:
      self.dict = attributes['dict']

    if 'packet' in attributes:
      self.decode_packet(attributes['packet'])

    for (key, value) in attributes.items():
      if key in ['dict', 'fd', 'packet']:
        continue
      key = key.replace('_', '-')
      self.add_attribute(key, value)

  def create_reply(self, **attributes):
    """Create a new packet as a reply to this one. This method
    makes sure the authenticator and secret are copied over
    to the new instance.
    """
    return Packet(id=self.id, secret=self.secret,
           authenticator=self.authenticator, dict=self.dict,
           **attributes)

  def _decode_value(self, attr, value): # pylint: disable=no-self-use
    if attr.values.has_backward(value):
      return attr.values.get_backward(value)
    else:
      return tools.decode_attr(attr.type, value)

  def _encode_value(self, attr, value):
    result = ''
    if attr.values.has_forward(value):
      result = attr.values.get_forward(value)
    else:
      result = tools.encode_attr(attr.type, value)

    if attr.encrypt == 2:
      # salt encrypt attribute
      result = self.salt_crypt(result)

    return result

  def _encode_key_values(self, key, values):
    if not isinstance(key, str):
      return (key, values)

    key, _, tag = key.partition(":")

    attr = self.dict.attributes[key]
    if attr.vendor:
      key = (self.dict.vendors.get_forward(attr.vendor), attr.code)
    else:
      key = attr.code

    if tag:
      tag = struct.pack('B', int(tag))
      if attr.type == "integer":
        return (key, [tag + self._encode_value(attr, v)[1:] for v in values])
      else:
        return (key, [tag + self._encode_value(attr, v) for v in values])
    else:
      return (key, [self._encode_value(attr, v) for v in values])

  def _encode_key(self, key):
    if not isinstance(key, str):
      return key

    attr = self.dict.attributes[key]
    if attr.vendor:
      return (self.dict.vendors.get_forward(attr.vendor), attr.code)
    else:
      return attr.code

  def _decode_key(self, key):
    """Turn a key into a string if possible"""

    if self.dict.attrindex.has_backward(key):
      return self.dict.attrindex.get_backward(key)
    return key

  def add_attribute(self, key, value):
    """Add an attribute to the packet.

    :param key: attribute name or identification
    :type key: string, attribute code or (vendor code, attribute code)
        tuple
    :param value: value
    :type value: depends on type of attribute
    """
    if isinstance(value, list):
      (key, value) = self._encode_key_values(key, value)
      self.setdefault(key, []).extend(value)
    else:
      (key, value) = self._encode_key_values(key, [value])
      value = value[0]
      self.setdefault(key, []).append(value)

  def __getitem__(self, key):
    if not isinstance(key, six.string_types):
      return dict.__getitem__(self, key)

    values = dict.__getitem__(self, self._encode_key(key))
    attr = self.dict.attributes[key]
    res = []
    for v in values:
      res.append(self._decode_value(attr, v))
    return res

  def __contains__(self, key):
    try:
      return dict.__contains__(self, self._encode_key(key))
    except KeyError:
      return False

  has_key = __contains__

  def __delitem__(self, key):
    dict.__delitem__(self, self._encode_key(key))

  def __setitem__(self, key, item):
    if isinstance(key, six.string_types):
      (key, item) = self._encode_key_values(key, [item])
      dict.__setitem__(self, key, item)
    else:
      assert isinstance(item, list)
      dict.__setitem__(self, key, item)

  def keys(self):
    return [self._decode_key(key) for key in dict.keys(self)]

  @staticmethod
  def create_authenticator():
    """Create a packet autenticator. All RADIUS packets contain a sixteen
    byte authenticator which is used to authenticate replies from the
    RADIUS server and in the password hiding algorithm. This function
    returns a suitable random string that can be used as an authenticator.

    :return: valid packet authenticator
    :rtype: binary string
    """

    data = []
    for i in range(16):
      data.append(RANDOMGENERATOR.randrange(0, 256))
    if six.PY3:
      return bytes(data)
    else:
      return ''.join(chr(b) for b in data)

  def create_id(self): # pylint: disable=no-self-use
    """Create a packet ID. All RADIUS requests have a ID which is used to
    identify a request. This is used to detect retries and replay attacks.
    This function returns a suitable random number that can be used as ID.

    :return: ID number
    :rtype: integer

    """
    return RANDOMGENERATOR.randrange(0, 256)

  def reply_packet(self):
    """Create a ready-to-transmit authentication reply packet.
    Returns a RADIUS packet which can be directly transmitted
    to a RADIUS server. This differs with Packet() in how
    the authenticator is calculated.

    :return: raw packet
    :rtype: string
    """
    assert self.authenticator
    assert(self.secret is not None)

    attr = self._pkt_encode_attributes()
    header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))

    authenticator = MD5Constructor(header[0:4] + self.authenticator
                    + attr + self.secret).digest()
    return header + authenticator + attr

  def verify_reply(self, reply, rawreply=None):
    if reply.id != self.id:
      return False

    if rawreply is None:
      rawreply = reply.reply_packet()

    hash = MD5Constructor(rawreply[0:4] + self.authenticator +
                rawreply[20:] + self.secret).digest()

    if hash != rawreply[4:20]:
      return False
    return True

  def _pkt_encode_attribute(self, key, value):
    if isinstance(key, tuple):
      value = struct.pack('!L', key[0]) + \
        self._pkt_encode_attribute(key[1], value)
      key = 26

    return struct.pack('!BB', key, (len(value) + 2)) + value

  def _pkt_encode_attributes(self):
    result = six.b('')
    for (code, datalst) in self.items():
      for data in datalst:
        result += self._pkt_encode_attribute(code, data)

    return result

  def _pkt_decode_vendor_attribute(self, data): # pylint: disable=no-self-use
    # Check if this packet is long enough to be in the
    # RFC2865 recommended form
    if len(data) < 6:
      return [(26, data)]

    (vendor, type, length) = struct.unpack('!LBB', data[:6])[0:3]

    tlvs = [((vendor, type), data[6:length + 4])]

    sumlength = 4 + length
    while len(data) > sumlength:
      try:
        type, length = struct.unpack(
          '!BB', data[sumlength:sumlength + 2])[0:2]
      except:
        return [(26, data)]
      tlvs.append(
        ((vendor, type), data[sumlength + 2:sumlength + length]))
      sumlength += length
    return tlvs

  def decode_packet(self, packet):
    """Initialize the object from raw packet data. Decode a packet as
    received from the network and decode it.

    :param packet: raw packet
    :type packet: string"""

    try:
      (self.code, self.id, length, self.authenticator) = \
        struct.unpack('!BBH16s', packet[0:20])
    except struct.error:
      raise PacketError('Packet header is corrupt')
    if len(packet) != length:
      raise PacketError('Packet has invalid length')
    if length > 8192:
      raise PacketError('Packet length is too long (%d)' % length)

    self.clear()

    packet = packet[20:]
    while packet:
      try:
        (key, attrlen) = struct.unpack('!BB', packet[0:2])
      except struct.error:
        raise PacketError('Attribute header is corrupt')

      if attrlen < 2:
        raise PacketError(
          'Attribute length is too small (%d)' % attrlen)

      value = packet[2:attrlen]
      if key == 26:
        for (key, value) in self._pkt_decode_vendor_attribute(value):
          self.setdefault(key, []).append(value)
      else:
        self.setdefault(key, []).append(value)

      packet = packet[attrlen:]

  def salt_crypt(self, value):
    """Salt Encryption

    :param value: plaintext value
    :type password: unicode string
    :return:   obfuscated version of the value
    :rtype:   binary string
    """

    if isinstance(value, six.text_type):
      value = value.encode('utf-8')

    if self.authenticator is None:
      # self.authenticator = self.create_authenticator()
      self.authenticator = 16 * six.b('\x00')

    salt = struct.pack('!H', RANDOMGENERATOR.randrange(0, 65535))
    salt = chr(ord(salt[0]) | 1 << 7) + salt[1]

    length = struct.pack("B", len(value))
    buf = length + value
    if len(buf) % 16 != 0:
      buf += six.b('\x00') * (16 - (len(buf) % 16))

    result = six.b(salt)

    last = self.authenticator + salt
    while buf:
      hash = MD5Constructor(self.secret + last).digest()
      if six.PY3:
        for i in range(16):
          result += bytes((hash[i] ^ buf[i],))
      else:
        for i in range(16):
          result += chr(ord(hash[i]) ^ ord(buf[i]))

      last = result[-16:]
      buf = buf[16:]

    return result


class AuthPacket(Packet):

  def __init__(self, code=ACCESSREQUEST, id=None, secret=six.b(''),
         authenticator=None, **attributes):
    """Constructor

    :param code: packet type code
    :type code: integer (8bits)
    :param id:  packet identifaction number
    :type id:  integer (8 bits)
    :param secret: secret needed to communicate with a RADIUS server
    :type secret: string

    :param dict: RADIUS dictionary
    :type dict: pyrad.dictionary.Dictionary class

    :param packet: raw packet to decode
    :type packet: string
    """
    Packet.__init__(self, code, id, secret, authenticator, **attributes)

  def create_reply(self, **attributes):
    """Create a new packet as a reply to this one. This method
    makes sure the authenticator and secret are copied over
    to the new instance.
    """
    return AuthPacket(ACCESSACCEPT, self.id,
             self.secret, self.authenticator, dict=self.dict,
             **attributes)

  def request_packet(self):
    """Create a ready-to-transmit authentication request packet.
    Return a RADIUS packet which can be directly transmitted
    to a RADIUS server.

    :return: raw packet
    :rtype: string
    """
    attr = self._pkt_encode_attributes()

    if self.authenticator is None:
      self.authenticator = self.create_authenticator()

    if self.id is None:
      self.id = self.create_id()

    header = struct.pack('!BBH16s', self.code, self.id,
              (20 + len(attr)), self.authenticator)

    return header + attr

  def pw_decrypt(self, password):
    """Unobfuscate a RADIUS password. RADIUS hides passwords in packets by
    using an algorithm based on the MD5 hash of the packet authenticator
    and RADIUS secret. This function reverses the obfuscation process.

    :param password: obfuscated form of password
    :type password: binary string
    :return:   plaintext password
    :rtype:   unicode string
    """
    buf = password
    pw = six.b('')

    last = self.authenticator
    while buf:
      hash = MD5Constructor(self.secret + last).digest()
      if six.PY3:
        for i in range(16):
          pw += bytes((hash[i] ^ buf[i],))
      else:
        for i in range(16):
          pw += chr(ord(hash[i]) ^ ord(buf[i]))

      (last, buf) = (buf[:16], buf[16:])

    while pw.endswith(six.b('\x00')):
      pw = pw[:-1]

    return pw.decode('utf-8')

  def PwCrypt(self, password):
    """Obfuscate password.
    RADIUS hides passwords in packets by using an algorithm
    based on the MD5 hash of the packet authenticator and RADIUS
    secret. If no authenticator has been set before calling PwCrypt
    one is created automatically. Changing the authenticator after
    setting a password that has been encrypted using this function
    will not work.

    :param password: plaintext password
    :type password: unicode stringn
    :return:   obfuscated version of the password
    :rtype:   binary string
    """
    if self.authenticator is None:
      self.authenticator = self.create_authenticator()

    if isinstance(password, six.text_type):
      password = password.encode('utf-8')

    buf = password
    if len(password) % 16 != 0:
      buf += six.b('\x00') * (16 - (len(password) % 16))

    hash = MD5Constructor(self.secret + self.authenticator).digest()
    result = six.b('')

    last = self.authenticator
    while buf:
      hash = MD5Constructor(self.secret + last).digest()
      if six.PY3:
        for i in range(16):
          result += bytes((hash[i] ^ buf[i],))
      else:
        for i in range(16):
          result += chr(ord(hash[i]) ^ ord(buf[i]))

      last = result[-16:]
      buf = buf[16:]

    return result

  def verify_chap_passwd(self, userpwd):
    """ Verify RADIUS ChapPasswd

    :param userpwd: plaintext password
    :type userpwd: str
    :return:  is verify ok
    :rtype:   bool
    """

    if not self.authenticator:
      self.authenticator = self.create_authenticator()

    if isinstance(userpwd, six.text_type):
      userpwd = userpwd.strip().encode('utf-8')

    chap_password = tools.decode_octets(self.get(3)[0])
    if len(chap_password) != 17:
      return False

    chapid = chap_password[0]
    password = chap_password[1:]

    challenge = self.authenticator
    if 'CHAP-Challenge' in self:
      challenge = self['CHAP-Challenge'][0]

    return password == MD5Constructor("%s%s%s" %
            (chapid, userpwd, challenge)).digest()


class AcctPacket(Packet):

  """RADIUS accounting packets. This class is a specialization
  of the generic :obj:`Packet` class for accounting packets.
  """

  def __init__(self, code=ACCOUNTINGREQUEST, id=None, secret=six.b(''),
         authenticator=None, **attributes):
    """Constructor

    :param dict: RADIUS dictionary
    :type dict: pyrad.dictionary.Dictionary class
    :param secret: secret needed to communicate with a RADIUS server
    :type secret: string
    :param id:  packet identifaction number
    :type id:  integer (8 bits)
    :param code: packet type code
    :type code: integer (8bits)
    :param packet: raw packet to decode
    :type packet: string
    """
    Packet.__init__(self, code, id, secret, authenticator, **attributes)
    if 'packet' in attributes:
      self.raw_packet = attributes['packet']

  def create_reply(self, **attributes):
    """Create a new packet as a reply to this one. This method
    makes sure the authenticator and secret are copied over
    to the new instance.
    """
    return AcctPacket(ACCOUNTINGRESPONSE, self.id,
             self.secret, self.authenticator, dict=self.dict,
             **attributes)

  def verify_acct_request(self):
    """Verify request authenticator.

    :return: True if verification failed else False
    :rtype: boolean
    """
    assert self.raw_packet
    hash = MD5Constructor(self.raw_packet[0:4] + 16 * six.b('\x00') +
                self.raw_packet[20:] + self.secret).digest()
    return hash == self.authenticator

  def request_packet(self):
    """Create a ready-to-transmit authentication request packet.
    Return a RADIUS packet which can be directly transmitted
    to a RADIUS server.

    :return: raw packet
    :rtype: string
    """

    attr = self._pkt_encode_attributes()

    if self.id is None:
      self.id = self.create_id()

    header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
    self.authenticator = MD5Constructor(header[0:4] + 16 * six.b('\x00') + attr
                       + self.secret).digest()
    return header + self.authenticator + attr


class CoAPacket(Packet):

  """RADIUS CoA packets. This class is a specialization
  of the generic :obj:`Packet` class for CoA packets.
  """

  def __init__(self, code=COAREQUEST, id=None, secret=six.b(''),
         authenticator=None, **attributes):
    """Constructor

    :param dict: RADIUS dictionary
    :type dict: pyrad.dictionary.Dictionary class
    :param secret: secret needed to communicate with a RADIUS server
    :type secret: string
    :param id:  packet identifaction number
    :type id:  integer (8 bits)
    :param code: packet type code
    :type code: integer (8bits)
    :param packet: raw packet to decode
    :type packet: string
    """
    Packet.__init__(self, code, id, secret, authenticator, **attributes)
    if 'packet' in attributes:
      self.raw_packet = attributes['packet']

  def create_reply(self, **attributes):
    """Create a new packet as a reply to this one. This method
    makes sure the authenticator and secret are copied over
    to the new instance.
    """
    return CoAPacket(COAACK, self.id,
             self.secret, self.authenticator, dict=self.dict,
             **attributes)

  def verify_coa_request(self):
    """Verify request authenticator.

    :return: True if verification failed else False
    :rtype: boolean
    """
    assert self.raw_packet
    hash = MD5Constructor(self.raw_packet[0:4] + 16 * six.b('\x00') +
                self.raw_packet[20:] + self.secret).digest()
    return hash == self.authenticator

  def request_packet(self):
    """Create a ready-to-transmit CoA request packet.
    Return a RADIUS packet which can be directly transmitted
    to a RADIUS server.

    :return: raw packet
    :rtype: string
    """

    attr = self._pkt_encode_attributes()

    if self.id is None:
      self.id = self.create_id()

    header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
    self.authenticator = MD5Constructor(header[0:4] + 16 * six.b('\x00') + attr
                       + self.secret).digest()
    return header + self.authenticator + attr


def create_id():
  """Generate a packet ID.

  :return: packet ID
  :rtype: 8 bit integer
  """
  global CURRENTID # pylint: disable=global-statement

  CURRENTID = (CURRENTID + 1) % 256
  return CURRENTID
