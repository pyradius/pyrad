# packet.py
#
# Copyright 2002-2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS packet as defined in RFC 2138


import struct, types, random, UserDict
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new
from pyrad import tools

# Packet codes
AccessRequest       = 1
AccessAccept        = 2
AccessReject        = 3
AccountingRequest   = 4
AccountingResponse  = 5
AccessChallenge     = 11
StatusServer        = 12
StatusClient        = 13
DisconnectRequest   = 40
DisconnectACK       = 41
DisconnectNAK       = 42
CoARequest      = 43
CoAACK          = 44
CoANAK          = 45

# Current ID
CurrentID       = random.randrange(1, 255)

class PacketError(Exception):
    pass


class Packet(UserDict.UserDict):
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

    def __init__(self, code=0, id=None, secret="", authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identifaction number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        UserDict.UserDict.__init__(self)
        self.code=code
        if id is not None:
            self.id=id
        else:
            self.id=CreateID()
        self.secret=secret
        self.authenticator=authenticator

        if attributes.has_key("dict"):
            self.dict=attributes["dict"]

        if attributes.has_key("packet"):
            self.DecodePacket(attributes["packet"])

        for (key,value) in attributes.items():
            if key in [ "dict", "fd", "packet"]:
                continue

            key=key.replace("_", "-")
            self.AddAttribute(key, value)


    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """

        return Packet(id=self.id, secret=self.secret,
                      authenticator=self.authenticator, dict=self.dict,
                      **attributes)


    def _DecodeValue(self, attr, value):
        if attr.values.HasBackward(value):
            return attr.values.GetBackward(value)
        else:
            return tools.DecodeAttr(attr.type, value)


    def _EncodeValue(self, attr, value):
        if attr.values.HasForward(value):
            return attr.values.GetForward(value)
        else:
            return tools.EncodeAttr(attr.type, value)


    def _EncodeKeyValues(self, key, values):
        if not isinstance(key, str):
            return (key, values)

        attr=self.dict.attributes[key]

        if attr.vendor:
            key=(self.dict.vendors.GetForward(attr.vendor), attr.code)
        else:
            key=attr.code

        return (key, [self._EncodeValue(attr, v) for v in values])


    def _EncodeKey(self, key):
        if not isinstance(key, str):
            return key

        attr=self.dict.attributes[key]
        if attr.vendor:
            return (self.dict.vendors.GetForward(attr.vendor), attr.code)
        else:
            return attr.code


    def _DecodeKey(self, key):
        "Turn a key into a string if possible"

        if self.dict.attrindex.HasBackward(key):
            return self.dict.attrindex.GetBackward(key)

        return key


    def AddAttribute(self, key, value):
        """Add an attribute to the packet.

        :param key:   attribute name or identification
        :type key:    string, attribute code or (vendor code, attribute code) tuple
        :param value: value
        :type value:  depends on type of attribute
        """
        (key,value)=self._EncodeKeyValues(key, [value])
        value=value[0]

        if self.data.has_key(key):
            self.data[key].append(value)
        else:
            self.data[key]=[value]


    def __getitem__(self, key):
        if type(key)!=types.StringType:
            return self.data[key]

        values=self.data[self._EncodeKey(key)]
        attr=self.dict.attributes[key]
        res=[]
        for v in values:
            res.append(self._DecodeValue(attr, v))
        return res


    def __contains__(self, key):
        return self.has_key(key)


    def has_key(self, key):
        try:
            return self.data.has_key(self._EncodeKey(key))
        except KeyError:
            return False


    def __delitem__(self, key):
        del self.data[self._EncodeKey(key)]


    def __setitem__(self, key, item):
        if type(key)==types.StringType:
            (key,item)=self._EncodeKeyValues(key, [item])
            self.data[key]=item
        else:
            assert isinstance(item, list)
            self.data[key]=item


    def keys(self):
        return [self._DecodeKey(key) for key in self.data.keys()]


    def CreateAuthenticator():
        """Create a packet autenticator. All RADIUS packets contain a sixteen
        byte authenticator which is used to authenticate replies from the
        RADIUS server and in the password hiding algorithm. This function
        returns a suitable random string that can be used as an authenticator.

        :return: valid packet authenticator
        :rtype: string
        """

        data=""
        for i in range(16):
            data+=chr(random.randrange(0,256))

        return data
    CreateAuthenticator=staticmethod(CreateAuthenticator)


    def CreateID(self):
        """Create a packet ID.  All RADIUS requests have a ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        :return: ID number
        :rtype:  integer

        """
        return random.randrange(0,256)


    def ReplyPacket(self):
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        :return: raw packet
        :rtype:  string
        """
        assert(self.authenticator)
        assert(self.secret)

        attr=self._PktEncodeAttributes()
        header=struct.pack("!BBH", self.code, self.id, (20+len(attr)))

        authenticator=md5_constructor(header[0:4] + self.authenticator
                              + attr + self.secret).digest()

        return header + authenticator + attr


    def VerifyReply(self, reply, rawreply=None):
        if reply.id!=self.id:
            return False

        if rawreply is None:
            rawreply=reply.ReplyPacket()

        hash=md5_constructor(rawreply[0:4] + self.authenticator + 
                     rawreply[20:] + self.secret).digest()

        if hash!=rawreply[4:20]:
            return False

        return True


    def _PktEncodeAttribute(self, key, value):
        if type(key)==types.TupleType:
            value=struct.pack("!L", key[0]) + \
                self._PktEncodeAttribute(key[1], value)
            key=26

        return struct.pack("!BB", key, (len(value)+2))+value


    def _PktEncodeAttributes(self):
        result=""
        for (code, datalst) in self.items():
            for data in datalst:
                result+=self._PktEncodeAttribute(code, data)

        return result


    def _PktDecodeVendorAttribute(self, data):
        # Check if this packet is long enough to be in the
        # RFC2865 recommended form
        if len(data)<6:
            return (26, data)

        (vendor, type, length)=struct.unpack("!LBB", data[:6])[0:3]
        # Another sanity check
        if len(data)!=length+4:
            return (26,data)

        return ((vendor,type), data[6:])


    def DecodePacket(self, packet):
        """Initialize the object from raw packet data.  Decode a packet as
        received from the network and decode it.

        :param packet: raw packet
        :type packet:  string"""

        try:
            (self.code, self.id, length, self.authenticator)=struct.unpack("!BBH16s", packet[0:20])
        except struct.error:
            raise PacketError, "Packet header is corrupt"
        if len(packet)!=length:
            raise PacketError, "Packet has invalid length"
        if length>8192:
            raise PacketError, "Packet length is too long (%d)" % length

        self.clear()

        packet=packet[20:]
        while packet:
            try:
                (key, attrlen)=struct.unpack("!BB", packet[0:2])
            except struct.error:
                raise PacketError, "Attribute header is corrupt"

            if attrlen<2:
                raise PacketError, "Attribute length is too small (%d)" % attrlen

            value=packet[2:attrlen]
            if key==26:
                (key,value)=self._PktDecodeVendorAttribute(value)

            if self.data.has_key(key):
                self.data[key].append(value)
            else:
                self.data[key]=[value]

            packet=packet[attrlen:]


class AuthPacket(Packet):
    def __init__(self, code=AccessRequest, id=None, secret="", authenticator=None, **attributes):
        """Constructor

        :param code:   packet type code
        :type code:    integer (8bits)
        :param id:     packet identifaction number
        :type id:      integer (8 bits)
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class

        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)


    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AuthPacket(AccessAccept, self.id,
            self.secret, self.authenticator, dict=self.dict,
            **attributes)


    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr=self._PktEncodeAttributes()

        if self.authenticator is None:
            self.authenticator=self.CreateAuthenticator()

        if self.id is None:
            self.id=self.CreateID()

        header=struct.pack("!BBH16s", self.code, self.id,
            (20+len(attr)), self.authenticator)

        return header+attr


    def PwDecrypt(self, password):
        """Unobfuscate a RADIUS password. RADIUS hides passwords in packets by
        using an algorithm based on the MD5 hash of the packet authenticator
        and RADIUS secret. This function reverses the obfuscation process.

        :param password: obfuscated form of password
        :type password:  string
        :return:         plaintext password
        :rtype:          string
        """

        buf=password
        pw=""

        last=self.authenticator
        while buf:
            hash=md5_constructor(self.secret+last).digest()
            for i in range(16):
                pw+=chr(ord(hash[i]) ^ ord(buf[i]))

            (last,buf)=(buf[:16], buf[16:])

        while pw.endswith("\x00"):
            pw=pw[:-1]

        return pw


    def PwCrypt(self, password):
        """Obfuscate password.
        RADIUS hides passwords in packets by using an algorithm
        based on the MD5 hash of the packet authenticator and RADIUS
        secret. If no authenticator has been set before calling PwCrypt
        one is created automatically. Changing the authenticator after
        setting a password that has been encrypted using this function
        will not work.

        :param password: plaintext password
        :type password:  string
        :return:         obfuscated version of the password
        :rtype:          string
        """
        if self.authenticator is None:
            self.authenticator=self.CreateAuthenticator()

        buf=password
        if len(password)%16!=0:
            buf+="\x00" * (16-(len(password)%16))

        hash=md5_constructor(self.secret+self.authenticator).digest()
        result=""

        last=self.authenticator
        while buf:
            hash=md5_constructor(self.secret+last).digest()
            for i in range(16):
                result+=chr(ord(hash[i]) ^ ord(buf[i]))

            last=result[-16:]
            buf=buf[16:]

        return result


class AcctPacket(Packet):
    """RADIUS accounting packets. This class is a specialization
    of the generic :obj:`Packet` class for accounting packets.
    """

    def __init__(self, code=AccountingRequest, id=None, secret="", authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identifaction number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        if attributes.has_key("packet"):
            self.raw_packet=attributes["packet"]


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

        :return: True if verification failed else False
        :rtype: boolean
        """
        assert(self.raw_packet)
        hash=md5_constructor(self.raw_packet[0:4] + 16*"\x00" + 
                self.raw_packet[20:] + self.secret).digest()

        return hash==self.authenticator


    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr=self._PktEncodeAttributes()

        if self.id is None:
            self.id=self.CreateID()

        header=struct.pack("!BBH", self.code, self.id, (20+len(attr)))

        self.authenticator=md5_constructor(header[0:4] + 16 * "\x00" + attr
            + self.secret).digest()

        return header + self.authenticator + attr


def CreateID():
    """Generate a packet ID.

    :return: packet ID
    :rtype:  8 bit integer
    """
    global CurrentID

    CurrentID=(CurrentID+1)%256
    return CurrentID

