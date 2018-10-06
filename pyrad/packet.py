# packet.py
#
# Copyright 2002-2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS packet as defined in RFC 2138


import random
import struct
from hashlib import md5
from os import urandom

from pyrad import tools

# Packet codes
AccessRequest = 1
AccessAccept = 2
AccessReject = 3
AccountingRequest = 4
AccountingResponse = 5
AccessChallenge = 11
StatusServer = 12
StatusClient = 13
DisconnectRequest = 40
DisconnectACK = 41
DisconnectNAK = 42
CoARequest = 43
CoAACK = 44
CoANAK = 45

# Use cryptographic-safe random generator as provided by the OS.
random_generator = random.SystemRandom()


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

    def __init__(self, code: int = 0, packet_id: int = None, secret: bytes = b'', authenticator: bytes = None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param packet_id:     packet identifaction number
        :type packet_id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        super().__init__()

        self.code = code
        if packet_id is not None:
            self.packet_id = packet_id
        else:
            self.packet_id = self.create_id()
        if not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.secret = secret
        if authenticator is not None and not isinstance(authenticator, bytes):
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
        return Packet(packet_id=self.packet_id, secret=self.secret,
                      authenticator=self.authenticator, dict=self.dict,
                      **attributes)

    @staticmethod
    def _decode_value(attr, value):
        if attr.values.has_backward(value):
            return attr.values.get_backward(value)
        else:
            return tools.DecodeAttr(attr.type, value)

    def _encode_value(self, attr, value):
        if attr.values.has_forward(value):
            result = attr.values.get_forward(value)
        else:
            result = tools.EncodeAttr(attr.type, value)

        if attr.encrypt == 2:
            # salt encrypt attribute
            result = self.salt_crypt(result)

        return result

    def _encode_key_values(self, key, values):
        if not isinstance(key, str):
            return key, values

        key, _, tag = key.partition(":")
        attr = self.dict.attributes[key]
        key = self._encode_key(key)
        if tag:
            tag = struct.pack('B', int(tag))
            if attr.type == "integer":
                return key, [tag + self._encode_value(attr, v)[1:] for v in values]
            else:
                return key, [tag + self._encode_value(attr, v) for v in values]
        else:
            return key, [self._encode_value(attr, v) for v in values]

    def _encode_key(self, key):
        if not isinstance(key, str):
            return key

        attr = self.dict.attributes[key]
        if attr.vendor and not attr.is_sub_attribute:  # sub attribute keys don't need vendor
            return self.dict.vendors.get_forward(attr.vendor), attr.code
        else:
            return attr.code

    def _decode_key(self, key):
        """Turn a key into a string if possible"""

        if self.dict.attrindex.has_backward(key):
            return self.dict.attrindex.get_backward(key)
        return key

    def add_attribute(self, key, value):
        """add an attribute to the packet.

        :param key:   attribute name or identification
        :type key:    string, attribute code or (vendor code, attribute code)
                      tuple
        :param value: value
        :type value:  depends on type of attribute
        """
        attr = self.dict.attributes[key]

        if isinstance(value, list):
            (key, value) = self._encode_key_values(key, value)
        else:
            (key, value) = self._encode_key_values(key, [value])

        if attr.is_sub_attribute:
            tlv = self.setdefault(self._encode_key(attr.parent.name), {})
            encoded = tlv.setdefault(key, [])
        else:
            encoded = self.setdefault(key, [])

        encoded.extend(value)

    def __getitem__(self, key):
        if not isinstance(key, str):
            return dict.__getitem__(self, key)

        values = dict.__getitem__(self, self._encode_key(key))
        attr = self.dict.attributes[key]
        if attr.type == 'tlv':  # return map from sub attribute code to its values
            res = {}
            for (sub_attr_key, sub_attr_val) in values.items():
                sub_attr_name = attr.sub_attributes[sub_attr_key]
                sub_attr = self.dict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    res.setdefault(sub_attr_name, []).append(self._decode_value(sub_attr, v))
            return res
        else:
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
        if isinstance(key, str):
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
            data.append(random_generator.randrange(0, 256))
        return bytes(data)

    @staticmethod
    def create_id():
        """Create a packet ID.  All RADIUS requests have a ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        :return: ID number
        :rtype:  integer

        """
        return random_generator.randrange(0, 256)

    def reply_packet(self):
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        :return: raw packet
        :rtype:  string
        """
        assert self.authenticator
        assert self.secret is not None

        attr = self._pkt_encode_attributes()
        header = struct.pack('!BBH', self.code, self.packet_id, (20 + len(attr)))

        authenticator = md5(header[0:4] + self.authenticator
                            + attr + self.secret).digest()
        return header + authenticator + attr

    def verify_reply(self, reply, raw_reply=None):
        if reply.packet_id != self.packet_id:
            return False

        if raw_reply is None:
            raw_reply = reply.reply_packet()

        md5_hash = md5(raw_reply[0:4] + self.authenticator +
                       raw_reply[20:] + self.secret).digest()

        if md5_hash != raw_reply[4:20]:
            return False
        return True

    def _pkt_encode_attribute(self, key, value):
        if isinstance(key, tuple):
            value = struct.pack('!L', key[0]) + \
                    self._pkt_encode_attribute(key[1], value)
            key = 26

        return struct.pack('!BB', key, (len(value) + 2)) + value

    def _pkt_encode_tlv(self, tlv_key, tlv_value):
        tlv_attr = self.dict.attributes[self._decode_key(tlv_key)]
        curr_avp = b''
        avps = []
        max_sub_attribute_len = max(map(lambda item: len(item[1]), tlv_value.items()))
        for i in range(max_sub_attribute_len):
            sub_attr_encoding = b''
            for (code, datalst) in tlv_value.items():
                if i < len(datalst):
                    sub_attr_encoding += self._pkt_encode_attribute(code, datalst[i])
            # split above 255. assuming len of one instance of all sub tlvs is lower than 255
            if (len(sub_attr_encoding) + len(curr_avp)) < 245:
                curr_avp += sub_attr_encoding
            else:
                avps.append(curr_avp)
                curr_avp = sub_attr_encoding
        avps.append(curr_avp)
        tlv_avps = []
        for avp in avps:
            value = struct.pack('!BB', tlv_attr.code, (len(avp) + 2)) + avp
            tlv_avps.append(value)
        if tlv_attr.vendor:
            vendor_avps = b''
            for avp in tlv_avps:
                vendor_avps += struct.pack(
                    '!BBL', 26, (len(avp) + 6),
                    self.dict.vendors.get_forward(tlv_attr.vendor)
                ) + avp
            return vendor_avps
        else:
            return b''.join(tlv_avps)

    def _pkt_encode_attributes(self):
        result = b''
        for (code, datalst) in self.items():
            if self.dict.attributes[self._decode_key(code)].type == 'tlv':
                result += self._pkt_encode_tlv(code, datalst)
            else:
                for data in datalst:
                    result += self._pkt_encode_attribute(code, data)
        return result

    def _pkt_decode_vendor_attribute(self, data):
        # Check if this packet is long enough to be in the
        # RFC2865 recommended form
        if len(data) < 6:
            return [(26, data)]

        vendor, pkt_type, length = struct.unpack('!LBB', data[:6])[0:3]

        try:
            if self.dict.attributes[self._decode_key((vendor, pkt_type))].type == 'tlv':
                self._pkt_decode_tlv_attribute((vendor, pkt_type), data[6:length + 4])
                tlvs = []  # tlv is added to the packet inside _pkt_decode_tlv_attribute
            else:
                tlvs = [((vendor, pkt_type), data[6:length + 4])]
        except Exception:  # why ??
            return [(26, data)]

        sumlength = 4 + length
        while len(data) > sumlength:
            try:
                pkt_type, length = struct.unpack('!BB', data[sumlength:sumlength + 2])[0:2]
            except Exception:  # why ??
                return [(26, data)]
            tlvs.append(((vendor, pkt_type), data[sumlength + 2:sumlength + length]))
            sumlength += length
        return tlvs

    def _pkt_decode_tlv_attribute(self, code, data):

        sub_attributes = self.setdefault(code, {})
        loc = 0

        while loc < len(data):
            pkt_type, length = struct.unpack('!BB', data[loc:loc + 2])[0:2]
            sub_attributes.setdefault(pkt_type, []).append(data[loc + 2:loc + length])
            loc += length

    def decode_packet(self, packet: bytes):
        """Initialize the object from raw packet data.  Decode a packet as
        received from the network and decode it.

        :param packet: raw packet
        :type packet:  string"""

        try:
            self.code, self.packet_id, length, self.authenticator = struct.unpack('!BBH16s', packet[0:20])
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
            elif self.dict.attributes[self._decode_key(key)].type == 'tlv':
                self._pkt_decode_tlv_attribute(key, value)
            else:
                self.setdefault(key, []).append(value)

            packet = packet[attrlen:]

    def salt_crypt(self, value: str):
        """Salt Encryption

        :param value:    plaintext value
        :return:         obfuscated version of the value
        :rtype:          binary string
        """

        if isinstance(value, str):
            value = value.encode('utf-8')

        if self.authenticator is None:
            # self.authenticator = self.create_authenticator()
            self.authenticator = 16 * b'\x00'

        salt = bytes([random.randint(128, 255)]) + urandom(1)

        length = struct.pack("B", len(value))
        buf = length + value
        if len(buf) % 16 != 0:
            buf += b'\x00' * (16 - (len(buf) % 16))

        result = salt

        last = self.authenticator + salt
        while buf:
            md5_hash = md5(self.secret + last).digest()
            for i in range(16):
                result += bytes((md5_hash[i] ^ buf[i],))

            last = result[-16:]
            buf = buf[16:]

        return result


class AuthPacket(Packet):
    def __init__(self, code: int = AccessRequest, packet_id: int = None, secret: bytes = b'', authenticator: bytes = None, **attributes):
        """Constructor

        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet_id:     packet identifaction number
        :type packet_id:      integer (8 bits)
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class

        :param packet: raw packet to decode
        :type packet:  string
        """
        super().__init__(code, packet_id, secret, authenticator, **attributes)
        if 'packet' in attributes:
            self.raw_packet = attributes['packet']

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AuthPacket(AccessAccept, self.packet_id,
                          self.secret, self.authenticator, dict=self.dict,
                          **attributes)

    def request_packet(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """
        attr = self._pkt_encode_attributes()

        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        if self.packet_id is None:
            self.packet_id = self.create_id()

        header = struct.pack('!BBH16s', self.code, self.packet_id,
                             (20 + len(attr)), self.authenticator)

        return header + attr

    def pw_decrypt(self, password):
        """Unobfuscate a RADIUS password. RADIUS hides passwords in packets by
        using an algorithm based on the MD5 hash of the packet authenticator
        and RADIUS secret. This function reverses the obfuscation process.

        :param password: obfuscated form of password
        :type password:  binary string
        :return:         plaintext password
        :rtype:          unicode string
        """
        buf = password
        pw = b''

        last = self.authenticator
        while buf:
            md5_hash = md5(self.secret + last).digest()
            for i in range(16):
                pw += bytes((md5_hash[i] ^ buf[i],))
            (last, buf) = (buf[:16], buf[16:])

        while pw.endswith(b'\x00'):
            pw = pw[:-1]

        return pw.decode('utf-8')

    def pw_crypt(self, password):
        """Obfuscate password.
        RADIUS hides passwords in packets by using an algorithm
        based on the MD5 hash of the packet authenticator and RADIUS
        secret. If no authenticator has been set before calling pw_crypt
        one is created automatically. Changing the authenticator after
        setting a password that has been encrypted using this function
        will not work.

        :param password: plaintext password
        :type password:  unicode stringn
        :return:         obfuscated version of the password
        :rtype:          binary string
        """
        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        if isinstance(password, str):
            password = password.encode('utf-8')

        buf = password
        if len(password) % 16 != 0:
            buf += b'\x00' * (16 - (len(password) % 16))

        result = b''

        last = self.authenticator
        while buf:
            md5_hash = md5(self.secret + last).digest()
            for i in range(16):
                result += bytes((md5_hash[i] ^ buf[i],))

            last = result[-16:]
            buf = buf[16:]

        return result

    def verify_chap_passwd(self, userpwd):
        """ Verify RADIUS ChapPasswd

        :param userpwd: plaintext password
        :type userpwd:  str
        :return:        is verify ok
        :rtype:         bool
        """

        if not self.authenticator:
            self.authenticator = self.create_authenticator()

        if isinstance(userpwd, str):
            userpwd = userpwd.strip().encode('utf-8')

        chap_password = tools.DecodeOctets(self.get(3)[0])
        if len(chap_password) != 17:
            return False

        chapid = chap_password[0]
        password = chap_password[1:]

        challenge = self.authenticator
        if 'CHAP-Challenge' in self:
            challenge = self['CHAP-Challenge'][0]

        return password == md5("%s%s%s" % (chapid, userpwd, challenge)).digest()

    def verify_auth_request(self):
        """Verify request authenticator.

        :return: True if verification failed else False
        :rtype: boolean
        """
        assert self.raw_packet
        md5_hash = md5(self.raw_packet[0:4] + 16 * b'\x00' + self.raw_packet[20:] + self.secret).digest()
        return md5_hash == self.authenticator


class AcctPacket(Packet):
    """RADIUS accounting packets. This class is a specialization
    of the generic :obj:`Packet` class for accounting packets.
    """

    def __init__(self, code: int = AccountingRequest, packet_id: int = None, secret: bytes = b'', authenticator: bytes = None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param packet_id:     packet identifaction number
        :type packet_id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        super().__init__(code, packet_id, secret, authenticator, **attributes)
        if 'packet' in attributes:
            self.raw_packet = attributes['packet']

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AcctPacket(AccountingResponse, self.packet_id,
                          self.secret, self.authenticator, dict=self.dict,
                          **attributes)

    def verify_acct_request(self):
        """Verify request authenticator.

        :return: True if verification failed else False
        :rtype: boolean
        """
        assert self.raw_packet
        md5_hash = md5(self.raw_packet[0:4] + 16 * b'\x00' + self.raw_packet[20:] + self.secret).digest()
        return md5_hash == self.authenticator

    def request_packet(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr = self._pkt_encode_attributes()

        if self.packet_id is None:
            self.packet_id = self.create_id()

        header = struct.pack('!BBH', self.code, self.packet_id, (20 + len(attr)))
        self.authenticator = md5(header[0:4] + 16 * b'\x00' + attr
                                 + self.secret).digest()
        return header + self.authenticator + attr


class CoAPacket(Packet):
    """RADIUS CoA packets. This class is a specialization
    of the generic :obj:`Packet` class for CoA packets.
    """

    def __init__(self, code: int = CoARequest, packet_id: int = None, secret: bytes = b'', authenticator: bytes = None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param packet_id:     packet identifaction number
        :type packet_id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        super().__init__(code, packet_id, secret, authenticator, **attributes)
        if 'packet' in attributes:
            self.raw_packet = attributes['packet']

    def create_reply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return CoAPacket(CoAACK, self.packet_id,
                         self.secret, self.authenticator, dict=self.dict,
                         **attributes)

    def verify_coa_request(self):
        """Verify request authenticator.

        :return: True if verification failed else False
        :rtype: boolean
        """
        assert self.raw_packet
        md5_hash = md5(self.raw_packet[0:4] + 16 * b'\x00' +
                       self.raw_packet[20:] + self.secret).digest()
        return md5_hash == self.authenticator

    def request_packet(self):
        """Create a ready-to-transmit CoA request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr = self._pkt_encode_attributes()

        if self.packet_id is None:
            self.packet_id = self.create_id()

        header = struct.pack('!BBH', self.code, self.packet_id, (20 + len(attr)))
        self.authenticator = md5(header[0:4] + 16 * b'\x00' + attr
                                 + self.secret).digest()
        return header + self.authenticator + attr
