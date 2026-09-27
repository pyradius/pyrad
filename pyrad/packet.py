# packet.py
#
# Copyright 2002-2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS packet as defined in RFC 2138

from collections import OrderedDict
from pyrad import tools
import hashlib
import hmac
import secrets
import struct

random_generator = secrets.SystemRandom()


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
    names are used pyrad takes care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    Attributes with the has_tag flag (RFC 2868) take a tag after the
    name, for example ``pkt['Tunnel-Type:1']``. Without a tag the values
    of all tags are returned.

    Normally you will not use this class directly, but one of the
    :obj:`AuthPacket`, :obj:`AcctPacket` or :obj:`CoAPacket` classes.
    """

    def __init__(self, code=0, id=None, secret=b'', authenticator=None,
                 **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  bytes
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8 bits)
        :param packet: raw packet to decode
        :type packet:  bytes
        :param authenticator: request or response authenticator
        :type authenticator:  bytes
        :param message_authenticator: add a Message-Authenticator
        :type message_authenticator:  bool
        :param attributes: attributes to add, with ``-`` in the attribute
                           names replaced by ``_``
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
        self.request_authenticator = None      # used for storing request authenticator in reply packets
        self._request_code = None              # code of the request in reply packets
        self.message_authenticator = None
        self.raw_packet = None

        self.dict = attributes.get('dict')

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
        """Add a Message-Authenticator (RFC 2869 section 5.14) as first
        attribute, as recommended as countermeasure against the BlastRADIUS
        attack (CVE-2024-3596). The value is calculated when the packet is
        encoded.
        """
        self.message_authenticator = True
        # Maintain a zero octets content for md5 and hmac calculation.
        self._set_message_authenticator(16 * b'\00')

        if self.id is None:
            self.id = self.CreateID()

        if self.authenticator is None and self.code == AccessRequest:
            self.authenticator = self.CreateAuthenticator()
            self._refresh_message_authenticator()

    def get_message_authenticator(self):
        self._refresh_message_authenticator()
        return self.message_authenticator

    def _set_message_authenticator(self, value):
        # Use the attribute code, the dictionary may not define it
        present = OrderedDict.__contains__(self, 80)
        OrderedDict.__setitem__(self, 80, [value])
        if not present:
            self.move_to_end(80, last=False)

    def _message_authenticator_vector(self, original_authenticator=None,
                                      original_code=None):
        """Return the authenticator used for the Message-Authenticator
        calculation (RFC 2869 section 5.14, RFC 5176 section 3.3,
        RFC 5997 section 3).
        """
        if self.code in (AccountingRequest, DisconnectRequest, CoARequest) or \
                (self.code == AccountingResponse and original_code != StatusServer):
            return 16 * b'\00'

        if self.code in (AccessRequest, StatusServer):
            authenticator = self.authenticator
        else:
            # NOTE: self.authenticator on reply packet is initialized
            #       with request authenticator by design, but it contains
            #       the response authenticator for decoded replies.
            authenticator = original_authenticator or self.authenticator

        if authenticator is None:
            raise Exception('No authenticator found')
        return authenticator

    def _refresh_message_authenticator(self):
        hmac_constructor = hmac.new(self.secret, digestmod='MD5')

        # Maintain a zero octets content for md5 and hmac calculation.
        self._set_message_authenticator(16 * b'\00')
        attr = self._PktEncodeAttributes()

        header = struct.pack('!BBH', self.code, self.id,
                             (20 + len(attr)))

        hmac_constructor.update(header[0:4])
        hmac_constructor.update(self._message_authenticator_vector(
            original_code=getattr(self, '_request_code', None)))
        hmac_constructor.update(attr)
        self._set_message_authenticator(hmac_constructor.digest())

    @staticmethod
    def _zero_message_authenticator(attr):
        """Return raw attributes with the Message-Authenticator value zeroed."""
        loc = 0
        while loc + 2 <= len(attr):
            (key, length) = struct.unpack('!BB', attr[loc:loc+2])
            if length < 2:
                break
            if key == 80:
                return attr[:loc+2] + 16 * b'\00' + attr[loc+length:]
            loc += length
        return attr

    def verify_message_authenticator(self, secret=None,
                                     original_authenticator=None,
                                     original_code=None):
        """Verify packet Message-Authenticator.

        To verify a received reply, the authenticator and code of the
        request must be passed as original_authenticator and original_code.

        :return: False if verification failed else True
        :rtype: boolean
        """
        if self.message_authenticator is None:
            raise Exception('No Message-Authenticator AVP present')

        prev_ma = OrderedDict.__getitem__(self, 80)
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
            attr = self._zero_message_authenticator(self.raw_packet[20:])
        else:
            # Set zero bytes for Message-Authenticator for md5 calculation
            self._set_message_authenticator(16 * b'\00')
            attr = self._PktEncodeAttributes()
            self._set_message_authenticator(prev_ma[0])

        header = struct.pack('!BBH', self.code, self.id,
                             (20 + len(attr)))

        hmac_constructor = hmac.new(key, digestmod='MD5')
        hmac_constructor.update(header)
        hmac_constructor.update(self._message_authenticator_vector(
            original_authenticator, original_code))
        hmac_constructor.update(attr)
        return hmac.compare_digest(prev_ma[0], hmac_constructor.digest())

    def _PrepareReply(self, reply, attributes):
        """Copy Proxy-State attributes unmodified and in order into a new
        reply (RFC 2865 section 5.33). Nothing is changed if the reply is
        decoded from a received packet.

        The code of this request is kept in the reply, the
        Message-Authenticator of an Accounting-Response to a Status-Server
        is calculated with the Request Authenticator (RFC 5997 section 3).
        """
        reply._request_code = self.code
        if 'packet' not in attributes and OrderedDict.__contains__(self, 33) \
                and not OrderedDict.__contains__(reply, 33):
            OrderedDict.__setitem__(reply, 33, list(OrderedDict.__getitem__(self, 33)))
        return reply

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return self._PrepareReply(
            Packet(id=self.id, secret=self.secret,
                   authenticator=self.authenticator, dict=self.dict,
                   **attributes), attributes)

    def _DecodeValue(self, attr, value):
        if attr.encrypt == 2:
            # salt decrypt attribute
            value = self.SaltDecrypt(value)

        if attr.values.HasBackward(value):
            return attr.values.GetBackward(value)
        else:
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
            tag = int(tag)
            if not 0 <= tag <= 0x1F:
                raise ValueError('Invalid tag %d for attribute %s' % (tag, attr.name))
            tag = struct.pack('B', tag)
        elif attr.has_tag and attr.encrypt == 2:
            # RFC 2868 section 3.5: the tag of Tunnel-Password is not optional
            tag = b'\x00'
        if tag:
            if attr.type == "integer":
                return (key, [tag + self._EncodeValue(attr, v)[1:] for v in values])
            else:
                return (key, [tag + self._EncodeValue(attr, v) for v in values])
        else:
            return (key, [self._EncodeValue(attr, v) for v in values])

    @staticmethod
    def _SplitTag(attr, value):
        """Split a raw value of a tagged attribute (RFC 2868 section 3) into
        its tag and value. The tag replaces the first octet of integers and
        always precedes the salt of encrypted values. For other types it is
        optional and present if the first octet is at most 0x1F.
        """
        if not attr.has_tag or not value:
            return (0, value)
        if attr.type == 'integer':
            return (value[0], b'\x00' + value[1:])
        if attr.encrypt == 2 or value[0] <= 0x1F:
            return (value[0], value[1:])
        return (0, value)

    def _EncodeKey(self, key):
        if not isinstance(key, str):
            return key

        attr = self.dict.attributes[key]
        if attr.vendor and not attr.is_sub_attribute:  # sub attribute keys don't need vendor
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
        The values are appended to existing values of the attribute. Raw
        values of attributes which are not in the dictionary are set with
        ``pkt[code] = [value]`` instead.

        :param key:   attribute name, with an optional tag for attributes
                      with the has_tag flag (``'Tunnel-Type:1'``)
        :type key:    string
        :param value: value or list of values
        :type value:  depends on type of attribute
        """
        if not isinstance(key, str):
            raise TypeError('Attribute key must be an attribute name, not %s; '
                            'use pkt[code] = [value] for raw values'
                            % type(key).__name__)
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

        key, _, tag = key.partition(':')
        values = OrderedDict.__getitem__(self, self._EncodeKey(key))
        attr = self.dict.attributes[key]
        if attr.type == 'tlv':  # return map from sub attribute code to its values
            res = {}
            for (sub_attr_key, sub_attr_val) in values.items():
                sub_attr_name = attr.sub_attributes.get(sub_attr_key)
                if sub_attr_name is None:
                    # undefined sub-attribute: raw values keyed by its code
                    res.setdefault(sub_attr_key, []).extend(sub_attr_val)
                    continue
                sub_attr = self.dict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    res.setdefault(sub_attr_name, []).append(self._DecodeValue(sub_attr, v))
            return res
        else:
            res = []
            for v in values:
                (value_tag, v) = self._SplitTag(attr, v)
                if not tag or value_tag == int(tag):
                    res.append(self._DecodeValue(attr, v))
            if tag and not res:
                raise KeyError('%s:%s' % (key, tag))
            return res

    def __contains__(self, key):
        try:
            if isinstance(key, str) and ':' in key:
                self.__getitem__(key)
                return True
            return OrderedDict.__contains__(self, self._EncodeKey(key))
        except KeyError:
            return False

    has_key = __contains__

    def __delitem__(self, key):
        OrderedDict.__delitem__(self, self._EncodeKey(key))

    def __setitem__(self, key, item):
        if isinstance(key, str):
            attr = self.dict.attributes[key.partition(':')[0]]
            (key, item) = self._EncodeKeyValues(key, item)
            if attr.is_sub_attribute:
                # sub-attributes are stored in the TLV of their parent,
                # like AddAttribute does
                tlv = self.setdefault(self._EncodeKey(attr.parent.name), {})
                tlv[key] = item
            else:
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
        :rtype: bytes
        """
        return bytes(
            random_generator.randrange(0, 256)
            for _ in range(16)
        )

    def CreateID(self):
        """Create a packet ID.  All RADIUS requests have an ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        :return: ID number
        :rtype:  integer

        """
        return random_generator.randrange(0, 256)

    def ReplyPacket(self):
        """Create a ready-to-transmit reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS client. This differs from RequestPacket() in how
        the authenticator is calculated.

        :return: raw packet
        :rtype:  bytes
        """
        assert (self.authenticator)
        assert (self.secret is not None)

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))

        authenticator = hashlib.md5(header[0:4] + self.authenticator
                                    + attr + self.secret).digest()

        return header + authenticator + attr

    def VerifyReply(self, reply, rawreply=None, enforce_ma=False):
        """Verify that a reply belongs to this request.
        Checks the packet ID and the response authenticator and, as
        countermeasure against the BlastRADIUS attack (CVE-2024-3596),
        the Message-Authenticator and the Proxy-State attributes.

        :param reply:      reply packet
        :type reply:       pyrad.packet.Packet
        :param rawreply:   reply as received from the network, defaults
                           to the raw packet the reply was decoded from
        :type rawreply:    bytes
        :param enforce_ma: require a Message-Authenticator in replies to
                           Access-Request and Status-Server packets
        :type enforce_ma:  bool
        :return:           True if the reply is valid else False
        :rtype:            bool
        """
        if reply.id != self.id:
            return False

        if rawreply is None:
            if reply.raw_packet is not None:
                # a received reply: verify the bytes it was decoded from.
                # ReplyPacket would sign it again with its own (response)
                # authenticator and modify its Message-Authenticator.
                rawreply = reply.raw_packet
            else:
                # a locally built reply: verify it as it would be sent
                rawreply = reply.ReplyPacket()
        elif len(rawreply) >= 4:
            # ignore padding after the Length field (RFC 2865 section 3)
            rawreply = rawreply[:struct.unpack('!H', rawreply[2:4])[0]]

        # The Authenticator field in an Accounting-Response packet is called
        # the Response Authenticator, and contains a one-way MD5 hash
        # calculated over a stream of octets consisting of the Accounting
        # Response Code, Identifier, Length, the Request Authenticator field
        # from the Accounting-Request packet being replied to, and the
        # response attributes if any, followed by the shared secret.  The
        # resulting 16 octet MD5 hash value is stored in the Authenticator
        # field of the Accounting-Response packet.
        hash = hashlib.md5(rawreply[0:4] + self.authenticator +
                           rawreply[20:] + self.secret).digest()

        if not hmac.compare_digest(hash, rawreply[4:20]):
            return False

        # BlastRADIUS (CVE-2024-3596) countermeasures
        if OrderedDict.__contains__(reply, 80):
            if not reply.verify_message_authenticator(
                    secret=self.secret,
                    original_authenticator=self.authenticator,
                    original_code=self.code):
                return False
        elif enforce_ma and self.code in (AccessRequest, StatusServer):
            return False

        if self.code in (AccessRequest, StatusServer):
            # Proxy-State attributes in the reply which were not sent in
            # the request are the signature of the attack.
            sent = OrderedDict.get(self, 33, [])
            received = OrderedDict.get(reply, 33, [])
            if received != sent[:len(received)]:
                return False

        return True

    @staticmethod
    def _CheckAttributeLength(key, length):
        """Raise ValueError if an attribute with a value of length octets
        does not fit into the one octet Length field (RFC 2865 section 5).
        """
        if length + 2 > 255:
            raise ValueError('Value of attribute %r is too long (%d octets, '
                             'at most 253 fit into an attribute)'
                             % (key, length))

    def _PktEncodeAttribute(self, key, value):
        if isinstance(key, tuple):
            inner = self._PktEncodeAttribute(key[1], value)
            # vendor id and vendor attribute inside a Vendor-Specific
            # attribute (RFC 2865 section 5.26)
            self._CheckAttributeLength(key, 4 + len(inner))
            value = struct.pack('!L', key[0]) + inner
            key = 26
        else:
            self._CheckAttributeLength(key, len(value))

        return struct.pack('!BB', key, (len(value) + 2)) + value

    def _PktEncodeTlv(self, tlv_key, tlv_value):
        tlv_attr = self.dict.attributes[self._DecodeKey(tlv_key)]
        curr_avp = b''
        avps = []
        max_sub_attribute_len = max(map(lambda item: len(item[1]), tlv_value.items()),
                                    default=0)
        for i in range(max_sub_attribute_len):
            sub_attr_encoding = b''
            for (code, datalst) in tlv_value.items():
                if i < len(datalst):
                    sub_attr_encoding += self._PktEncodeAttribute(code, datalst[i])
            # split above 255. assuming len of one instance of all sub tlvs is lower than 255
            if (len(sub_attr_encoding) + len(curr_avp)) < 245:
                curr_avp += sub_attr_encoding
            else:
                if curr_avp:
                    avps.append(curr_avp)
                curr_avp = sub_attr_encoding
        avps.append(curr_avp)
        tlv_avps = []
        for avp in avps:
            self._CheckAttributeLength(tlv_attr.name, len(avp))
            value = struct.pack('!BB', tlv_attr.code, (len(avp) + 2)) + avp
            tlv_avps.append(value)
        if tlv_attr.vendor:
            vendor_avps = b''
            for avp in tlv_avps:
                self._CheckAttributeLength(tlv_attr.name, 4 + len(avp))
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
            if self._PktIsTlvAttribute(code):
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

        vendor = struct.unpack('!L', data[:4])[0]
        sub_attributes = self._PktSplitSubAttributes(data, 4)
        if sub_attributes is None:
            # Sub-attribute lengths do not add up, keep the raw attribute
            return [(26, data)]

        if getattr(self, 'dict', None) is None:
            # without a dictionary the attribute is kept raw
            return [(26, data)]

        attributes = []
        for (atype, value) in sub_attributes:
            if self._PktIsTlvAttribute((vendor, atype)):
                # tlv is added to the packet inside _PktDecodeTlvAttribute
                self._PktDecodeTlvAttribute((vendor, atype), value)
            else:
                attributes.append(((vendor, atype), value))
        return attributes

    @staticmethod
    def _PktSplitSubAttributes(data, loc=0):
        """Split data into (type, value) sub-attributes.

        :return: list of (type, value) tuples or None if the sub-attribute
                 lengths are invalid (RFC 2865 section 5.26)
        """
        sub_attributes = []
        while loc < len(data):
            if len(data) - loc < 2:
                return None
            (atype, length) = struct.unpack('!BB', data[loc:loc+2])
            if length < 2 or loc + length > len(data):
                return None
            sub_attributes.append((atype, data[loc+2:loc+length]))
            loc += length
        return sub_attributes

    def _PktDecodeTlvAttribute(self, code, data):
        sub_attributes = self._PktSplitSubAttributes(data)
        if sub_attributes is None:
            raise PacketError('TLV sub-attribute length is invalid')

        tlv = self.setdefault(code, {})
        for (atype, value) in sub_attributes:
            tlv.setdefault(atype, []).append(value)

    def _PktIsTlvAttribute(self, code):
        if getattr(self, 'dict', None) is None:
            return False
        attr = self.dict.attributes.get(self._DecodeKey(code))
        return (attr is not None and attr.type == 'tlv')

    def DecodePacket(self, packet):
        """Initialize the object from raw packet data.
        Decode a packet as received from the network.

        :param packet: raw packet
        :type packet:  bytes
        """

        try:
            (self.code, self.id, length, self.authenticator) = \
                    struct.unpack('!BBH16s', packet[0:20])

        except struct.error:
            raise PacketError('Packet header is corrupt')
        if length < 20 or len(packet) < length:
            raise PacketError('Packet has invalid length')
        if length > 8192:
            raise PacketError('Packet length is too long (%d)' % length)

        # RFC 2865 section 3: octets outside the range of the Length field
        # MUST be treated as padding and ignored on reception.
        packet = packet[:length]
        self.raw_packet = packet

        self.clear()

        packet = packet[20:]
        while packet:
            try:
                (key, attrlen) = struct.unpack('!BB', packet[0:2])
            except struct.error:
                raise PacketError('Attribute header is corrupt')

            if attrlen < 2:
                raise PacketError('Attribute length is too small (%d)' % attrlen)

            value = packet[2:attrlen]
            if key == 26:
                for (key, value) in self._PktDecodeVendorAttribute(value):
                    self.setdefault(key, []).append(value)
            elif key == 80:
                # POST: Message Authenticator AVP is present.
                self.message_authenticator = True
                self.setdefault(key, []).append(value)
            elif self._PktIsTlvAttribute(key):
                self._PktDecodeTlvAttribute(key, value)
            else:
                self.setdefault(key, []).append(value)

            packet = packet[attrlen:]

    def _salt_vector(self):
        """Return the authenticator used for salt encryption."""
        if self.request_authenticator is not None:
            # reply: the Request Authenticator of the request
            return self.request_authenticator
        if self.code in (AccountingRequest, CoARequest, DisconnectRequest):
            # the Request Authenticator of these requests is calculated over
            # the encrypted attributes, so they are encrypted with zeros,
            # like FreeRADIUS does
            return 16 * b'\x00'
        if self.authenticator is None:
            if self.code in (AccessRequest, StatusServer):
                # RFC 2865 section 3: the Request Authenticator must be
                # unpredictable and unique
                self.authenticator = self.CreateAuthenticator()
            else:
                self.authenticator = 16 * b'\x00'
        return self.authenticator

    def _salt_en_decrypt(self, data, salt, encrypt=True):
        result = b''
        last = self._salt_vector() + salt
        while data:
            hash = hashlib.md5(self.secret + last).digest()
            block = b''
            for i in range(16):
                block += bytes((hash[i] ^ data[i],))
            result += block

            # RFC 2868 3.5: each block chains on the ciphertext block, which is the
            # output when encrypting but the input when decrypting. Chaining on the
            # output unconditionally corrupted every block past the first on decrypt.
            last = block if encrypt else data[:16]
            data = data[16:]
        return result

    def SaltCrypt(self, value):
        """Encrypt a value with the salt encryption of RFC 2868
        section 3.5 (attributes with encrypt=2).

        :param value:    plaintext value
        :type value:     str or bytes
        :return:         encrypted value including salt
        :rtype:          bytes
        :raise ValueError: if the value is longer than 255 octets
        """

        if isinstance(value, str):
            value = value.encode('utf-8')

        # create salt
        random_value = 32768 + random_generator.randrange(0, 32767)
        salt_raw = struct.pack('!H', random_value)

        # length prefixing
        if len(value) > 255:
            raise ValueError('Value is too long for salt encryption '
                             '(%d octets, at most 255)' % len(value))
        length = struct.pack("B", len(value))
        value = length + value

        # zero padding
        if len(value) % 16 != 0:
            value += b'\x00' * (16 - (len(value) % 16))

        return salt_raw + self._salt_en_decrypt(value, salt_raw)

    def SaltDecrypt(self, value):
        """Decrypt a value encrypted with the salt encryption of
        RFC 2868 section 3.5 (attributes with encrypt=2).

        :param value:   encrypted value including salt
        :type value:    bytes
        :return:        decrypted value
        :rtype:         bytes
        """
        if len(value) < 18 or (len(value) - 2) % 16:
            raise PacketError('Invalid length of salt encrypted value')

        # extract salt
        salt = value[:2]

        # decrypt
        value = self._salt_en_decrypt(value[2:], salt, encrypt=False)

        # remove padding
        length = value[0]
        value = value[1:length+1]

        return value


class AuthPacket(Packet):
    """RADIUS authentication packets. This class is a specialization
    of the generic :obj:`Packet` class for Access-Request, Status-Server
    and their replies.
    """

    def __init__(self, code=AccessRequest, id=None, secret=b'',
                 authenticator=None, auth_type='pap', **attributes):
        """Constructor

        :param code:   packet type code
        :type code:    integer (8 bits)
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  bytes
        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param packet: raw packet to decode
        :type packet:  bytes
        """

        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        self.auth_type = auth_type

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        reply = AuthPacket(AccessAccept, self.id,
                           self.secret, self.authenticator, dict=self.dict,
                           auth_type=self.auth_type, **attributes)
        if 'packet' not in attributes and 'message_authenticator' not in attributes \
                and self.code in (AccessRequest, StatusServer):
            # Always sign replies as countermeasure against BlastRADIUS
            reply.message_authenticator = True
        return self._PrepareReply(reply, attributes)

    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  bytes
        """
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if self.id is None:
            self.id = self.CreateID()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        if self.auth_type == 'eap-md5' and not self.message_authenticator:
            header = struct.pack(
                '!BBH16s', self.code, self.id, (20 + 18 + len(attr)), self.authenticator
            )
            digest = hmac.new(
                self.secret,
                header
                + attr
                + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), b''),
                digestmod='MD5'
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

        The password is decoded as UTF-8, the encoding RFC 2865 uses for
        text; invalid UTF-8 sequences (for example if the secret is wrong)
        are ignored.

        :param password: obfuscated form of password
        :type password:  bytes
        :return:         plaintext password
        :rtype:          str
        """
        if isinstance(password, str):
            # str values are created by DecodeString using strict UTF-8
            password = password.encode('utf-8')
        elif isinstance(password, bytearray):
            password = bytes(password)

        # RFC 2865 section 5.2: a multiple of 16 octets
        if len(password) % 16:
            raise PacketError('Invalid length of encrypted password (%d)'
                              % len(password))

        buf = password
        pw = b''

        last = self.authenticator
        while buf:
            hash = hashlib.md5(self.secret + last).digest()
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
        :type password:  str or bytes
        :return:         obfuscated version of the password
        :rtype:          bytes
        :raise ValueError: if the password is longer than 128 octets
        """
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if isinstance(password, str):
            password = password.encode('utf-8')

        # RFC 2865 section 5.2: the password is padded at the end with
        # nulls to a multiple of 16 octets, the encrypted value is 16 to
        # 128 octets long
        if len(password) > 128:
            raise ValueError('Password is longer than 128 octets (%d)'
                             % len(password))
        buf = password
        if not buf or len(buf) % 16 != 0:
            buf += b'\x00' * (16 - (len(buf) % 16))

        result = b''

        last = self.authenticator
        while buf:
            hash = hashlib.md5(self.secret + last).digest()
            for i in range(16):
                result += bytes((hash[i] ^ buf[i],))
            last = result[-16:]
            buf = buf[16:]

        return result

    def VerifyChapPasswd(self, userpwd):
        """Verify the CHAP-Password of an Access-Request (RFC 2865
        section 2.2). The CHAP-Challenge attribute is used as challenge
        if present, else the request authenticator.

        :param userpwd: plaintext password
        :type userpwd:  str or bytes
        :return:        True if the password matches else False, also if
                        there is no CHAP-Password attribute
        :rtype:         bool
        """

        if not self.authenticator:
            self.authenticator = self.CreateAuthenticator()

        if isinstance(userpwd, str):
            userpwd = userpwd.strip().encode('utf-8')

        chap_passwords = self.get(3)
        if not chap_passwords:
            return False
        chap_password = tools.DecodeOctets(chap_passwords[0])
        if len(chap_password) != 17:
            return False

        chapid = chap_password[:1]
        password = chap_password[1:]

        challenge = self.authenticator
        if 'CHAP-Challenge' in self:
            challenge = self['CHAP-Challenge'][0]
        return hmac.compare_digest(
            password, hashlib.md5(chapid + userpwd + challenge).digest())

    def VerifyAuthRequest(self):
        """Check whether the authenticator is an accounting-style request
        authenticator: the MD5 hash of the packet header, 16 zero octets,
        the attributes and the secret (as for Accounting-Request,
        RFC 2866 section 3).

        This is not a verification of Access-Request packets: their
        Request Authenticator is a random number (RFC 2865 section 3),
        so this check fails for them. Use verify_message_authenticator
        to authenticate an Access-Request or Status-Server packet with
        a Message-Authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert (self.raw_packet)
        hash = hashlib.md5(self.raw_packet[0:4] + 16 * b'\x00' +
                           self.raw_packet[20:] + self.secret).digest()
        return hmac.compare_digest(hash, self.authenticator)


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
        :type secret:  bytes
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8 bits)
        :param packet: raw packet to decode
        :type packet:  bytes
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        reply = AcctPacket(AccountingResponse, self.id,
                           self.secret, self.authenticator, dict=self.dict,
                           **attributes)
        if 'packet' not in attributes and 'message_authenticator' not in attributes \
                and self.code == StatusServer:
            # sign responses to Status-Server (RFC 5997 section 3), like
            # AuthPacket.CreateReply does
            reply.message_authenticator = True
        return self._PrepareReply(reply, attributes)

    def VerifyAcctRequest(self):
        """Verify request authenticator.

        The Request Authenticator of a Status-Server packet is random
        (RFC 5997 section 3), for these packets the Message-Authenticator
        is verified instead, and a packet without one fails verification.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert (self.raw_packet)

        if self.code == StatusServer:
            return bool(self.message_authenticator) and \
                self.verify_message_authenticator()

        hash = hashlib.md5(self.raw_packet[0:4] + 16 * b'\x00' +
                           self.raw_packet[20:] + self.secret).digest()

        return hmac.compare_digest(hash, self.authenticator)

    def RequestPacket(self):
        """Create a ready-to-transmit accounting request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        A Status-Server packet (RFC 5997 section 3) gets a random Request
        Authenticator, like an Access-Request, and a Message-Authenticator
        unless message_authenticator is set to False.

        :return: raw packet
        :rtype:  bytes
        """

        if self.id is None:
            self.id = self.CreateID()

        if self.code == StatusServer:
            return self._StatusServerPacket()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
        self.authenticator = hashlib.md5(header[0:4] + 16 * b'\x00' +
                                         attr + self.secret).digest()

        ans = header + self.authenticator + attr

        return ans

    def _StatusServerPacket(self):
        # RFC 5997 section 3: the Request Authenticator of Status-Server is
        # generated like the one of Access-Request (random) and
        # Status-Server packets must include a Message-Authenticator
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if self.message_authenticator is None:
            self.message_authenticator = True

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH16s', self.code, self.id,
                             (20 + len(attr)), self.authenticator)
        return header + attr


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
        :type secret:  bytes
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8 bits)
        :param packet: raw packet to decode
        :type packet:  bytes
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return self._PrepareReply(
            CoAPacket(CoAACK, self.id,
                      self.secret, self.authenticator, dict=self.dict,
                      **attributes), attributes)

    def VerifyCoARequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert (self.raw_packet)
        hash = hashlib.md5(self.raw_packet[0:4] + 16 * b'\x00' +
                           self.raw_packet[20:] + self.secret).digest()
        return hmac.compare_digest(hash, self.authenticator)

    def RequestPacket(self):
        """Create a ready-to-transmit CoA request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  bytes
        """

        if self.id is None:
            self.id = self.CreateID()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
        self.authenticator = hashlib.md5(header[0:4] + 16 * b'\x00' +
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
