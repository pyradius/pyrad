# packet.py
#
# Copyright 2002-2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS packet as defined in RFC 2138

from collections import OrderedDict
import struct
try:
    import secrets
    random_generator = secrets.SystemRandom()
except ImportError:
    import random
    random_generator = random.SystemRandom()
import hmac

import sys
if sys.version_info >= (3, 0):
    hmac_new = lambda *x, **y: hmac.new(*x, digestmod='MD5', **y)
else:
    hmac_new = hmac.new

try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new
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

# Current ID
CurrentID = random_generator.randrange(1, 255)


class PacketError(Exception):
    pass


class Packet(OrderedDict):
    """Packet acts like a standard python map to provide simple access
    to the RADIUS attributes. Since RADIUS allows for repeated
    attributes the value will always be a sequence. pyrad makes sure
    to preserve the ordering when encoding and decoding packets.

    There are two ways to use the map interface: if attribute
    names are used pyrad take care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    Normally you will not use this class directly, but one of the
    :obj:`AuthPacket` or :obj:`AcctPacket` classes.
    """

    def __init__(self, code=0, id=None, secret=b'', authenticator=None,
                 **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        OrderedDict.__init__(self)
        self.code = code
        if id is not None:
            self.id = id
        else:
            self.id = CreateID()
        if not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.secret = secret
        if authenticator is not None and \
                not isinstance(authenticator, bytes):
            raise TypeError('authenticator must be a binary string')
        self.authenticator = authenticator
        self.message_authenticator = None
        self.raw_packet = None

        if 'dict' in attributes:
            self.dict = attributes['dict']

        if 'packet' in attributes:
            self.raw_packet = attributes['packet']
            self.DecodePacket(self.raw_packet)

        if 'message_authenticator' in attributes:
            self.message_authenticator = attributes['message_authenticator']

        for (key, value) in attributes.items():
            if key in [
                'dict', 'fd', 'packet',
                'message_authenticator',
            ]:
                continue
            key = key.replace('_', '-')
            self.AddAttribute(key, value)

    def add_message_authenticator(self):

        self.message_authenticator = True
        # Maintain a zero octets content for md5 and hmac calculation.
        self['Message-Authenticator'] = 16 * b'\00'

        if self.id is None:
            self.id = self.CreateID()

        if self.authenticator is None and self.code == AccessRequest:
            self.authenticator = self.CreateAuthenticator()
            self._refresh_message_authenticator()

    def get_message_authenticator(self):
        self._refresh_message_authenticator()
        return self.message_authenticator

    def _refresh_message_authenticator(self):
        hmac_constructor = hmac_new(self.secret)

        # Maintain a zero octets content for md5 and hmac calculation.
        self['Message-Authenticator'] = 16 * b'\00'
        attr = self._PktEncodeAttributes()

        header = struct.pack('!BBH', self.code, self.id,
                             (20 + len(attr)))

        hmac_constructor.update(header[0:4])
        if self.code in (AccountingRequest, DisconnectRequest,
                         CoARequest, AccountingResponse):
            hmac_constructor.update(16 * b'\00')
        else:
            # NOTE: self.authenticator on reply packet is initialized
            #       with request authenticator by design.
            #       For AccessAccept, AccessReject and AccessChallenge
            #       it is needed use original Authenticator.
            #       For AccessAccept, AccessReject and AccessChallenge
            #       it is needed use original Authenticator.
            if self.authenticator is None:
                raise Exception('No authenticator found')
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self['Message-Authenticator'] = hmac_constructor.digest()

    def verify_message_authenticator(self, secret=None,
                                     original_authenticator=None,
                                     original_code=None):
        """Verify packet Message-Authenticator.

        :return: False if verification failed else True
        :rtype: boolean
        """
        if self.message_authenticator is None:
            raise Exception('No Message-Authenticator AVP present')

        prev_ma = self['Message-Authenticator']
        # Set zero bytes for Message-Authenticator for md5 calculation
        if secret is None and self.secret is None:
            raise Exception('Missing secret for HMAC/MD5 verification')

        if secret:
            key = secret
        else:
            key = self.secret

        # If there's a raw packet, use that to calculate the expected
        # Message-Authenticator. While the Packet class keeps multiple
        # instances of an attribute grouped together in the attribute list,
        # other applications may not. Using _PktEncodeAttributes to get
        # the attributes could therefore end up changing the attribute order
        # because of the grouping Packet does, which would cause
        # Message-Authenticator verification to fail. Using the raw packet
        # instead, if present, ensures the verification is done using the
        # attributes exactly as sent.
        if self.raw_packet:
            attr = self.raw_packet[20:]
            attr = attr.replace(prev_ma[0], 16 * b'\00')
        else:
            self['Message-Authenticator'] = 16 * b'\00'
            attr = self._PktEncodeAttributes()

        header = struct.pack('!BBH', self.code, self.id,
                             (20 + len(attr)))

        hmac_constructor = hmac_new(key)
        hmac_constructor.update(header)
        if self.code in (AccountingRequest, DisconnectRequest,
                         CoARequest, AccountingResponse):
            if original_code is None or original_code != StatusServer:
                # TODO: Handle Status-Server response correctly.
                hmac_constructor.update(16 * b'\00')
        elif self.code in (AccessAccept, AccessChallenge,
                           AccessReject):
            if original_authenticator is None:
                if self.authenticator:
                    # NOTE: self.authenticator on reply packet is initialized
                    #       with request authenticator by design.
                    original_authenticator = self.authenticator
                else:
                    raise Exception('Missing original authenticator')

            hmac_constructor.update(original_authenticator)
        else:
            # On Access-Request and Status-Server use dynamic authenticator
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self['Message-Authenticator'] = prev_ma[0]
        return prev_ma[0] == hmac_constructor.digest()

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return Packet(id=self.id, secret=self.secret,
                      authenticator=self.authenticator, dict=self.dict,
                      **attributes)

    def _DecodeValue(self, attr, value):

        if attr.encrypt == 2:
            #salt decrypt attribute
            value = self.SaltDecrypt(value)

        if attr.values.HasBackward(value):
            return attr.values.GetBackward(value)
        else:
            if attr.encrypt:
                return tools.DecodeAttr('octets', value)
            return tools.DecodeAttr(attr.type, value)

    def _EncodeValue(self, attr, value):
        result = ''
        if attr.values.HasForward(value):
            result = attr.values.GetForward(value)
        else:
            result = tools.EncodeAttr(attr.type, value)

        if attr.encrypt == 2:
            # salt encrypt attribute
            result = self.SaltCrypt(result)

        return result

    def _EncodeKeyValues(self, key, values):
        if not isinstance(key, str):
            return (key, values)

        if not isinstance(values, (list, tuple)):
            values = [values]

        key, _, tag = key.partition(":")
        attr = self.dict.attributes[key]
        key = self._EncodeKey(key)
        if tag:
            tag = struct.pack('B', int(tag))
            if attr.type == "integer":
                return (key, [tag + self._EncodeValue(attr, v)[1:] for v in values])
            else:
                return (key, [tag + self._EncodeValue(attr, v) for v in values])
        else:
            return (key, [self._EncodeValue(attr, v) for v in values])

    def _EncodeKey(self, key):
        if not isinstance(key, str):
            return key

        attr = self.dict.attributes[key]
        if attr.vendor and not attr.is_sub_attribute:  #sub attribute keys don't need vendor
            return (self.dict.vendors.GetForward(attr.vendor), attr.code)
        else:
            return attr.code

    def _DecodeKey(self, key):
        """Turn a key into a string if possible"""

        if self.dict.attrindex.HasBackward(key):
            return self.dict.attrindex.GetBackward(key)
        return key

    def AddAttribute(self, key, value):
        """Add an attribute to the packet.

        :param key:   attribute name or identification
        :type key:    string, attribute code or (vendor code, attribute code)
                      tuple
        :param value: value
        :type value:  depends on type of attribute
        """
        attr = self.dict.attributes[key.partition(':')[0]]

        (key, value) = self._EncodeKeyValues(key, value)

        if attr.is_sub_attribute:
            tlv = self.setdefault(self._EncodeKey(attr.parent.name), {})
            encoded = tlv.setdefault(key, [])
        else:
            encoded = self.setdefault(key, [])

        encoded.extend(value)

    def get(self, key, failobj=None):
        try:
            res = self.__getitem__(key)
        except KeyError:
            res = failobj
        return res

    def __getitem__(self, key):
        if not isinstance(key, str):
            return OrderedDict.__getitem__(self, key)

        values = OrderedDict.__getitem__(self, self._EncodeKey(key))
        attr = self.dict.attributes[key]
        if attr.type == 'tlv':  # return map from sub attribute code to its values
            res = {}
            for (sub_attr_key, sub_attr_val) in values.items():
                sub_attr_name = attr.sub_attributes[sub_attr_key]
                sub_attr = self.dict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    res.setdefault(sub_attr_name, []).append(self._DecodeValue(sub_attr, v))
            return res
        else:
            res = []
            for v in values:
                res.append(self._DecodeValue(attr, v))
            return res

    def __contains__(self, key):
        try:
            return OrderedDict.__contains__(self, self._EncodeKey(key))
        except KeyError:
            return False

    has_key = __contains__

    def __delitem__(self, key):
        OrderedDict.__delitem__(self, self._EncodeKey(key))

    def __setitem__(self, key, item):
        if isinstance(key, str):
            (key, item) = self._EncodeKeyValues(key, item)
            OrderedDict.__setitem__(self, key, item)
        else:
            OrderedDict.__setitem__(self, key, item)

    def keys(self):
        return [self._DecodeKey(key) for key in OrderedDict.keys(self)]

    @staticmethod
    def CreateAuthenticator():
        """Create a packet authenticator. All RADIUS packets contain a sixteen
        byte authenticator which is used to authenticate replies from the
        RADIUS server and in the password hiding algorithm. This function
        returns a suitable random string that can be used as an authenticator.

        :return: valid packet authenticator
        :rtype: binary string
        """
        return bytes(
            random_generator.randrange(0, 256)
            for _ in range(16)
        )

    def CreateID(self):
        """Create a packet ID.  All RADIUS requests have a ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        :return: ID number
        :rtype:  integer

        """
        return random_generator.randrange(0, 256)

    def ReplyPacket(self):
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        :return: raw packet
        :rtype:  string
        """
        assert(self.authenticator)

        assert(self.secret is not None)

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))

        authenticator = md5_constructor(header[0:4] + self.authenticator
                                        + attr + self.secret).digest()

        return header + authenticator + attr

    def VerifyReply(self, reply, rawreply=None):
        if reply.id != self.id:
            return False

        if rawreply is None:
            rawreply = reply.ReplyPacket()

        attr = reply._PktEncodeAttributes()
        # The Authenticator field in an Accounting-Response packet is called
        # the Response Authenticator, and contains a one-way MD5 hash
        # calculated over a stream of octets consisting of the Accounting
        # Response Code, Identifier, Length, the Request Authenticator field
        # from the Accounting-Request packet being replied to, and the
        # response attributes if any, followed by the shared secret.  The
        # resulting 16 octet MD5 hash value is stored in the Authenticator
        # field of the Accounting-Response packet.
        hash = md5_constructor(rawreply[0:4] + self.authenticator +
                               rawreply[20:] + self.secret).digest()

        if hash != rawreply[4:20]:
            return False
        return True

    def _PktEncodeAttribute(self, key, value):
        if isinstance(key, tuple):
            value = struct.pack('!L', key[0]) + \
                self._PktEncodeAttribute(key[1], value)
            key = 26

        return struct.pack('!BB', key, (len(value) + 2)) + value

    def _PktEncodeTlv(self, tlv_key, tlv_value):
        tlv_attr = self.dict.attributes[self._DecodeKey(tlv_key)]
        curr_avp = b''
        avps = []
        max_sub_attribute_len = max(map(lambda item: len(item[1]), tlv_value.items()))
        for i in range(max_sub_attribute_len):
            sub_attr_encoding = b''
            for (code, datalst) in tlv_value.items():
                if i < len(datalst):
                    sub_attr_encoding += self._PktEncodeAttribute(code, datalst[i])
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
                    self.dict.vendors.GetForward(tlv_attr.vendor)
                ) + avp
            return vendor_avps
        else:
            return b''.join(tlv_avps)

    def _PktEncodeAttributes(self):
        result = b''
        for (code, datalst) in self.items():
            attribute = self.dict.attributes.get(self._DecodeKey(code))
            if attribute and attribute.type == 'tlv':
                result += self._PktEncodeTlv(code, datalst)
            else:
                for data in datalst:
                    result += self._PktEncodeAttribute(code, data)
        return result

    def _PktDecodeVendorAttribute(self, data):
        # Check if this packet is long enough to be in the
        # RFC2865 recommended form
        if len(data) < 6:
            return [(26, data)]

        (vendor, atype, length) = struct.unpack('!LBB', data[:6])[0:3]
        attribute = self.dict.attributes.get(self._DecodeKey((vendor, atype)))
        try:
            if attribute and attribute.type == 'tlv':
                self._PktDecodeTlvAttribute((vendor, atype), data[6:length + 4])
                tlvs = []  # tlv is added to the packet inside _PktDecodeTlvAttribute
            else:
                tlvs = [((vendor, atype), data[6:length + 4])]
        except:
            return [(26, data)]

        sumlength = 4 + length
        while len(data) > sumlength:
            try:
                atype, length = struct.unpack('!BB', data[sumlength:sumlength+2])[0:2]
            except:
                return [(26, data)]
            tlvs.append(((vendor, atype), data[sumlength+2:sumlength+length]))
            sumlength += length
        return tlvs

    def _PktDecodeTlvAttribute(self, code, data):
        sub_attributes = self.setdefault(code, {})
        loc = 0

        while loc < len(data):
            atype, length = struct.unpack('!BB', data[loc:loc+2])[0:2]
            sub_attributes.setdefault(atype, []).append(data[loc+2:loc+length])
            loc += length

    def DecodePacket(self, packet):
        """Initialize the object from raw packet data.  Decode a packet as
        received from the network and decode it.

        :param packet: raw packet
        :type packet:  string"""

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
            attribute = self.dict.attributes.get(self._DecodeKey(key))
            if key == 26:
                for (key, value) in self._PktDecodeVendorAttribute(value):
                    self.setdefault(key, []).append(value)
            elif key == 80:
                # POST: Message Authenticator AVP is present.
                self.message_authenticator = True
                self.setdefault(key, []).append(value)
            elif attribute and attribute.type == 'tlv':
                self._PktDecodeTlvAttribute(key,value)
            else:
                self.setdefault(key, []).append(value)

            packet = packet[attrlen:]


    def _salt_en_decrypt(self, data, salt):
        result = b''
        last = self.authenticator + salt
        while data:
            hash = md5_constructor(self.secret + last).digest()
            for i in range(16):
                result += bytes((hash[i] ^ data[i],))

            last = result[-16:]
            data = data[16:]
        return result


    def SaltCrypt(self, value):
        """SaltEncrypt

        :param value:    plaintext value
        :type:           unicode string
        :return:         obfuscated version of the value
        :rtype:          binary string
        """

        if isinstance(value, str):
            value = value.encode('utf-8')

        if self.authenticator is None:
            # self.authenticator = self.CreateAuthenticator()
            self.authenticator = 16 * b'\x00'

        #create salt
        random_value = 32768 + random_generator.randrange(0, 32767)
        salt_raw = struct.pack('!H', random_value)

        #length prefixing
        length = struct.pack("B", len(value))
        value = length + value

        #zero padding
        if len(value) % 16 != 0:
            value += b'\x00' * (16 - (len(value) % 16))

        return salt_raw + self._salt_en_decrypt(value, salt_raw)

    def SaltDecrypt(self, value):
        """ SaltDecrypt

        :param value:   encrypted value including salt
        :type:          binary string
        :return:        decrypted plaintext string
        :rtype:         unicode string
        """
        #extract salt
        salt = value[:2]

        #decrypt
        value = self._salt_en_decrypt(value[2:], salt)

        #remove padding
        length = value[0]
        value = value[1:length+1]

        return value


class AuthPacket(Packet):
    def __init__(self, code=AccessRequest, id=None, secret=b'',
                 authenticator=None, auth_type='pap', **attributes):
        """Constructor

        :param code:   packet type code
        :type code:    integer (8bits)
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class

        :param packet: raw packet to decode
        :type packet:  string
        """

        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        self.auth_type = auth_type

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AuthPacket(AccessAccept, self.id,
                          self.secret, self.authenticator, dict=self.dict,
                          auth_type=self.auth_type, **attributes)

    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if self.id is None:
            self.id = self.CreateID()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        if self.auth_type == 'eap-md5':
            header = struct.pack(
                '!BBH16s', self.code, self.id, (20 + 18 + len(attr)), self.authenticator
            )
            digest = hmac_new(
                self.secret,
                header
                + attr
                + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), b''),
            ).digest()
            return (
                header
                + attr
                + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), digest)
            )

        header = struct.pack('!BBH16s', self.code, self.id,
                             (20 + len(attr)), self.authenticator)

        return header + attr

    def PwDecrypt(self, password):
        """De-Obfuscate a RADIUS password. RADIUS hides passwords in packets by
        using an algorithm based on the MD5 hash of the packet authenticator
        and RADIUS secret. This function reverses the obfuscation process.

        Although RFC2865 does not explicitly state UTF-8 for the password field,
        the rest of RFC2865 defines UTF-8 as the encoding expected for the decrypted password.


        :param password: obfuscated form of password
        :type password:  binary string
        :return:         plaintext password
        :rtype:          unicode string
        """
        buf = password
        pw = b''

        last = self.authenticator
        while buf:
            hash = md5_constructor(self.secret + last).digest()
            for i in range(16):
                pw += bytes((hash[i] ^ buf[i],))
            (last, buf) = (buf[:16], buf[16:])

        # This is safe even with UTF-8 encoding since no valid encoding of UTF-8
        # (other than encoding U+0000 NULL) will produce a bytestream containing 0x00 byte.
        while pw.endswith(b'\x00'):
            pw = pw[:-1]

        # If the shared secret with the client is not the same, then de-obfuscating the password
        # field may yield illegal UTF-8 bytes. Therefore, in order not to provoke an Exception here
        # (which would be not consistently generated since this will depend on the random data 
        # chosen by the client) we simply ignore un-parsable UTF-8 sequences.
        return pw.decode('utf-8', errors="ignore")

    def PwCrypt(self, password):
        """Obfuscate password.
        RADIUS hides passwords in packets by using an algorithm
        based on the MD5 hash of the packet authenticator and RADIUS
        secret. If no authenticator has been set before calling PwCrypt
        one is created automatically. Changing the authenticator after
        setting a password that has been encrypted using this function
        will not work.

        :param password: plaintext password
        :type password:  unicode string
        :return:         obfuscated version of the password
        :rtype:          binary string
        """
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if isinstance(password, str):
            password = password.encode('utf-8')

        buf = password
        if len(password) % 16 != 0:
            buf += b'\x00' * (16 - (len(password) % 16))

        result = b''

        last = self.authenticator
        while buf:
            hash = md5_constructor(self.secret + last).digest()
            for i in range(16):
                result += bytes((hash[i] ^ buf[i],))
            last = result[-16:]
            buf = buf[16:]

        return result

    def VerifyChapPasswd(self, userpwd):
        """ Verify RADIUS ChapPasswd

        :param userpwd: plaintext password
        :type userpwd:  str
        :return:        is verify ok
        :rtype:         bool
        """

        if not self.authenticator:
            self.authenticator = self.CreateAuthenticator()

        if isinstance(userpwd, str):
            userpwd = userpwd.strip().encode('utf-8')

        chap_password = tools.DecodeOctets(self.get(3)[0])
        if len(chap_password) != 17:
            return False

        chapid = chap_password[:1]
        password = chap_password[1:]

        challenge = self.authenticator
        if 'CHAP-Challenge' in self:
            challenge = self['CHAP-Challenge'][0]
        return password == md5_constructor(chapid + userpwd + challenge).digest()

    def VerifyAuthRequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert (self.raw_packet)
        hash = md5_constructor(self.raw_packet[0:4] + 16 * b'\x00' +
                               self.raw_packet[20:] + self.secret).digest()
        return hash == self.authenticator


class AcctPacket(Packet):
    """RADIUS accounting packets. This class is a specialization
    of the generic :obj:`Packet` class for accounting packets.
    """

    def __init__(self, code=AccountingRequest, id=None, secret=b'',
                 authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AcctPacket(AccountingResponse, self.id,
                          self.secret, self.authenticator, dict=self.dict,
                          **attributes)

    def VerifyAcctRequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert(self.raw_packet)

        hash = md5_constructor(self.raw_packet[0:4] + 16 * b'\x00' +
                               self.raw_packet[20:] + self.secret).digest()

        return hash == self.authenticator

    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        if self.id is None:
            self.id = self.CreateID()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
        self.authenticator = md5_constructor(header[0:4] + 16 * b'\x00' +
                                             attr + self.secret).digest()

        ans = header + self.authenticator + attr

        return ans


class CoAPacket(Packet):
    """RADIUS CoA packets. This class is a specialization
    of the generic :obj:`Packet` class for CoA packets.
    """

    def __init__(self, code=CoARequest, id=None, secret=b'',
            authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return CoAPacket(CoAACK, self.id,
                         self.secret, self.authenticator, dict=self.dict,
                         **attributes)

    def VerifyCoARequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert(self.raw_packet)
        hash = md5_constructor(self.raw_packet[0:4] + 16 * b'\x00' +
                               self.raw_packet[20:] + self.secret).digest()
        return hash == self.authenticator

    def RequestPacket(self):
        """Create a ready-to-transmit CoA request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr = self._PktEncodeAttributes()

        if self.id is None:
            self.id = self.CreateID()

        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
        self.authenticator = md5_constructor(header[0:4] + 16 * b'\x00' +
                                             attr + self.secret).digest()

        if self.message_authenticator:
            self._refresh_message_authenticator()
            attr = self._PktEncodeAttributes()
            self.authenticator = md5_constructor(header[0:4] + 16 * b'\x00' +
                                                 attr + self.secret).digest()

        return header + self.authenticator + attr


def CreateID():
    """Generate a packet ID.

    :return: packet ID
    :rtype:  8 bit integer
    """
    global CurrentID

    CurrentID = (CurrentID + 1) % 256
    return CurrentID
