import hmac
import os
import struct
import unittest
import six

from . import home

from collections import OrderedDict
from pyrad import packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new


class UtilityTests(unittest.TestCase):
    def testGenerateID(self):
        id = packet.CreateID()
        self.assertTrue(isinstance(id, int))
        newid = packet.CreateID()
        self.assertNotEqual(id, newid)


class PacketConstructionTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'simple'))

    def testBasicConstructor(self):
        pkt = self.klass()
        self.assertTrue(isinstance(pkt.code, int))
        self.assertTrue(isinstance(pkt.id, int))
        self.assertTrue(isinstance(pkt.secret, six.binary_type))

    def testNamedConstructor(self):
        pkt = self.klass(code=26, id=38, secret=six.b('secret'),
                         authenticator=six.b('authenticator'),
                         dict='fakedict')
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, six.b('secret'))
        self.assertEqual(pkt.authenticator, six.b('authenticator'))
        self.assertEqual(pkt.dict, 'fakedict')

    def testConstructWithDictionary(self):
        pkt = self.klass(dict=self.dict)
        self.assertTrue(pkt.dict is self.dict)

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        self.assertFalse(getattr(pkt, 'fd', None) is marker)

    def testSecretMustBeBytestring(self):
        self.assertRaises(TypeError, self.klass, secret=six.u('secret'))

    def testConstructorWithAttributes(self):
        pkt = self.klass(**{'Test-String' :'this works', 'dict' : self.dict})
        self.assertEqual(pkt['Test-String'], ['this works'])

    def testConstructorWithTlvAttribute(self):
        pkt = self.klass(**{
            'Test-Tlv-Str': 'this works',
            'Test-Tlv-Int': 10,
            'dict': self.dict
        })
        self.assertEqual(
            pkt['Test-Tlv'],
            {'Test-Tlv-Str': ['this works'], 'Test-Tlv-Int' : [10]}
        )


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.Packet(
            id=0, secret=six.b('secret'),
            authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def _create_reply_with_duplicate_attributes(self, request):
        """
        Creates a reply to the given request with multiple instances of the
        same attribute that also do not appear sequentially in the list. Used
        to ensure that methods providing authenticator and
        Message-Authenticator verification can handle the case where multiple
        instances of an given attribute do not appear sequentially in the
        attributes list.
        """
        # Manually build the packet since using packet.Packet will always group
        # attributes of the same type together
        attributes = self._get_attribute_bytes('Test-String', 'test')
        attributes += self._get_attribute_bytes('Test-Integer', 1)
        attributes += self._get_attribute_bytes('Test-String', 'test')
        attributes += self._get_attribute_bytes('Message-Authenticator',
                                                16 * six.b('\00'))

        header = struct.pack('!BBH', packet.AccessAccept,
                             request.id, (20 + len(attributes)))

        # Calculate the Message-Authenticator and update the attribute
        hmac_constructor = hmac.new(request.secret, None, md5_constructor)
        hmac_constructor.update(header + request.authenticator + attributes)
        updated_message_authenticator = hmac_constructor.digest()
        attributes = attributes.replace(six.b('\x00') * 16,
                                        updated_message_authenticator)

        # Calculate the response authenticator
        authenticator = md5_constructor(header
                                        + request.authenticator
                                        + attributes
                                        + request.secret).digest()

        reply_bytes = header + authenticator + attributes
        return packet.AuthPacket(packet=reply_bytes, dict=self.dict)

    def _get_attribute_bytes(self, attr_name, value):
        attr = self.dict.attributes[attr_name]
        attr_key = attr.code
        attr_value = packet.tools.EncodeAttr(attr.type, value)
        attr_len = len(attr_value) + 2
        return struct.pack('!BB', attr_key, attr_len) + attr_value

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer' : 10})
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testAttributeAccess(self):
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet['Test-Integer'], [10])
        self.assertEqual(self.packet[3], [six.b('\x00\x00\x00\x0a')])

        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet['Test-String'], ['dummy'])
        self.assertEqual(self.packet[1], [six.b('dummy')])

    def testAttributeValueAccess(self):
        self.packet['Test-Integer'] = 'Three'
        self.assertEqual(self.packet['Test-Integer'], ['Three'])
        self.assertEqual(self.packet[3], [six.b('\x00\x00\x00\x03')])

    def testVendorAttributeAccess(self):
        self.packet['Simplon-Number'] = 10
        self.assertEqual(self.packet['Simplon-Number'], [10])
        self.assertEqual(self.packet[(16, 1)], [six.b('\x00\x00\x00\x0a')])

        self.packet['Simplon-Number'] = 'Four'
        self.assertEqual(self.packet['Simplon-Number'], ['Four'])
        self.assertEqual(self.packet[(16, 1)], [six.b('\x00\x00\x00\x04')])

    def testRawAttributeAccess(self):
        marker = [six.b('')]
        self.packet[1] = marker
        self.assertTrue(self.packet[1] is marker)
        self.packet[(16, 1)] = marker
        self.assertTrue(self.packet[(16, 1)] is marker)

    def testEncryptedAttributes(self):
        self.packet['Test-Encrypted-String'] = 'dummy'
        self.assertEqual(self.packet['Test-Encrypted-String'], ['dummy'])
        
        self.packet['Test-Encrypted-Integer'] = 10
        self.assertEqual(self.packet['Test-Encrypted-Integer'], [10])

    def testHasKey(self):
        self.assertEqual(self.packet.has_key('Test-String'), False)
        self.assertEqual('Test-String' in self.packet, False)
        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet.has_key('Test-String'), True)
        self.assertEqual(self.packet.has_key(1), True)
        self.assertEqual(1 in self.packet, True)

    def testHasKeyWithUnknownKey(self):
        self.assertEqual(self.packet.has_key('Unknown-Attribute'), False)
        self.assertEqual('Unknown-Attribute' in self.packet, False)

    def testDelItem(self):
        self.packet['Test-String'] = 'dummy'
        del self.packet['Test-String']
        self.assertEqual(self.packet.has_key('Test-String'), False)
        self.packet['Test-String'] = 'dummy'
        del self.packet[1]
        self.assertEqual(self.packet.has_key('Test-String'), False)

    def testKeys(self):
        self.assertEqual(self.packet.keys(), [])
        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet.keys(), ['Test-String'])
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet.keys(), ['Test-String', 'Test-Integer'])
        OrderedDict.__setitem__(self.packet, 12345, None)
        self.assertEqual(self.packet.keys(),
                        ['Test-String', 'Test-Integer', 12345])

    def testCreateAuthenticator(self):
        a = packet.Packet.CreateAuthenticator()
        self.assertTrue(isinstance(a, six.binary_type))
        self.assertEqual(len(a), 16)

        b = packet.Packet.CreateAuthenticator()
        self.assertNotEqual(a, b)

    def testGenerateID(self):
        id = self.packet.CreateID()
        self.assertTrue(isinstance(id, int))
        newid = self.packet.CreateID()
        self.assertNotEqual(id, newid)

    def testReplyPacket(self):
        reply = self.packet.ReplyPacket()
        self.assertEqual(reply,
                six.b('\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
                      '\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7'))

    def testVerifyReply(self):
        reply = self.packet.CreateReply()
        self.assertEqual(self.packet.VerifyReply(reply), True)

        reply.id += 1
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.id = self.packet.id

        reply.secret = six.b('different')
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.secret = self.packet.secret

        reply.authenticator = six.b('X') * 16
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.authenticator = self.packet.authenticator

    def testVerifyReplyDuplicateAttributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        self.assertTrue(self.packet.VerifyReply(
            reply=reply,
            rawreply=reply.raw_packet))

    def testVerifyMessageAuthenticator(self):
        reply = self.packet.CreateReply(**{
            'Test-String': 'test',
            'Test-Integer': 3,
        })
        reply.code = packet.AccessAccept
        reply.add_message_authenticator()
        reply._refresh_message_authenticator()
        self.assertTrue(reply.verify_message_authenticator(
            secret=six.b('secret'),
            original_authenticator=self.packet.authenticator,
            original_code=self.packet.code))

        self.assertFalse(reply.verify_message_authenticator(
            secret=six.b('bad_secret'),
            original_authenticator=self.packet.authenticator,
            original_code=self.packet.code))

        self.assertFalse(reply.verify_message_authenticator(
            secret=six.b('secret'),
            original_authenticator=six.b('bad_authenticator'),
            original_code=self.packet.code))

    def testVerifyMessageAuthenticatorDuplicateAttributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        self.assertTrue(reply.verify_message_authenticator(
            secret=six.b('secret'),
            original_authenticator=self.packet.authenticator,
            original_code=packet.AccessRequest))

    def testPktEncodeAttribute(self):
        encode = self.packet._PktEncodeAttribute

        # Encode a normal attribute
        self.assertEqual(
                encode(1, six.b('value')),
                six.b('\x01\x07value'))
        # Encode a vendor attribute
        self.assertEqual(
                encode((1, 2), six.b('value')),
                six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value'))

    def testPktEncodeTlvAttribute(self):
        encode = self.packet._PktEncodeTlv

        # Encode a normal tlv attribute
        self.assertEqual(
                encode(4, {1:[six.b('value')], 2:[six.b('\x00\x00\x00\x02')]}),
                six.b('\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02'))

        # Encode a normal tlv attribute with several sub attribute instances
        self.assertEqual(
                encode(4, {1:[six.b('value'), six.b('other')], 2:[six.b('\x00\x00\x00\x02')]}),
                six.b('\x04\x16\x01\x07value\x02\x06\x00\x00\x00\x02\x01\x07other'))
        # Encode a vendor tlv attribute
        self.assertEqual(
                encode((16, 3), {1:[six.b('value')], 2:[six.b('\x00\x00\x00\x02')]}),
                six.b('\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02'))

    def testPktEncodeLongTlvAttribute(self):
        encode = self.packet._PktEncodeTlv

        long_str = 'a' * 245
        # Encode a long tlv attribute - check it is split between AVPs
        self.assertEqual(
                encode(4, {1:[six.b('value'), six.b(long_str)], 2:[six.b('\x00\x00\x00\x02')]}),
                six.b('\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02\x04\xf9\x01\xf7' + long_str))

        # Encode a long vendor tlv attribute
        first_avp = '\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02'
        second_avp = '\x1a\xff\x00\x00\x00\x10\x03\xf9\x01\xf7' + long_str
        self.assertEqual(
                encode((16, 3), {1:[six.b('value'), six.b(long_str)], 2:[six.b('\x00\x00\x00\x02')]}),
                six.b(first_avp + second_avp))

    def testPktEncodeAttributes(self):
        self.packet[1] = [six.b('value')]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                six.b('\x01\x07value'))

        self.packet.clear()
        self.packet[(16, 2)] = [six.b('value')]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                six.b('\x1a\x0d\x00\x00\x00\x10\x02\x07value'))

        self.packet.clear()
        self.packet[1] = [six.b('one'), six.b('two'), six.b('three')]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                six.b('\x01\x05one\x01\x05two\x01\x07three'))

        self.packet.clear()
        self.packet[1] = [six.b('value')]
        self.packet[(16, 2)] = [six.b('value')]
        self.assertEqual(
                self.packet._PktEncodeAttributes(),
                six.b('\x01\x07value\x1a\x0d\x00\x00\x00\x10\x02\x07value'))

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._PktDecodeVendorAttribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(six.b('')), [(26, six.b(''))])
        self.assertEqual(decode(six.b('12345')), [(26, six.b('12345'))])

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(
                decode(six.b('\x00\x00\x00\x01\x02\x06value')),
                [(26, six.b('\x00\x00\x00\x01\x02\x06value'))])

        # Proper RFC2865 recommended form
        self.assertEqual(
                decode(six.b('\x00\x00\x00\x10\x02\x07value')),
                [((16, 2), six.b('value'))])

    def testPktDecodeTlvAttribute(self):
        decode = self.packet._PktDecodeTlvAttribute

        decode(4,six.b('\x01\x07value'))
        self.assertEqual(self.packet[4], {1: [six.b('value')]})

        #add another instance of the same sub attribute
        decode(4,six.b('\x01\x07other'))
        self.assertEqual(self.packet[4], {1: [six.b('value'), six.b('other')]})

        #add a different sub attribute
        decode(4,six.b('\x02\x07\x00\x00\x00\x01'))
        self.assertEqual(self.packet[4], {
            1: [six.b('value'), six.b('other')],
            2: [six.b('\x00\x00\x00\x01')]
        })

    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.DecodePacket(six.b(''))
        except packet.PacketError as e:
            self.assertTrue('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.DecodePacket(six.b('\x00\x00\x00\x001234567890123456'))
        except packet.PacketError as e:
            self.assertTrue('invalid length' in str(e))
        else:
            self.fail()

    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.DecodePacket(six.b('\x00\x00\x24\x00') + (0x2400 - 4) * six.b('X'))
        except packet.PacketError as e:
            self.assertTrue('too long' in str(e))
        else:
            self.fail()

    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.DecodePacket(
                    six.b('\x01\x02\x00\x151234567890123456\x00'))
        except packet.PacketError as e:
            self.assertTrue('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithoutAttributes(self):
        self.packet.DecodePacket(six.b('\x01\x02\x00\x141234567890123456'))
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, six.b('1234567890123456'))
        self.assertEqual(self.packet.keys(), [])

    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.DecodePacket(
                    six.b('\x01\x02\x00\x161234567890123456\x00\x01'))
        except packet.PacketError as e:
            self.assertTrue('too small' in str(e))
        else:
            self.fail()

    def testDecodePacketWithEmptyAttribute(self):
        self.packet.DecodePacket(
                six.b('\x01\x02\x00\x161234567890123456\x01\x02'))
        self.assertEqual(self.packet[1], [six.b('')])

    def testDecodePacketWithAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1b1234567890123456\x01\x07value'))
        self.assertEqual(self.packet[1], [six.b('value')])

    def testDecodePacketWithTlvAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value'))
        self.assertEqual(self.packet[4], {1:[six.b('value')]})

    def testDecodePacketWithVendorTlvAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x231234567890123456\x1a\x0f\x00\x00\x00\x10\x03\x09\x01\x07value'))
        self.assertEqual(self.packet[(16,3)], {1:[six.b('value')]})

    def testDecodePacketWithTlvAttributeWith2SubAttributes(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x231234567890123456\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x09'))
        self.assertEqual(self.packet[4], {1:[six.b('value')], 2:[six.b('\x00\x00\x00\x09')]})

    def testDecodePacketWithSplitTlvAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x251234567890123456\x04\x09\x01\x07value\x04\x09\x02\x06\x00\x00\x00\x09'))
        self.assertEqual(self.packet[4], {1:[six.b('value')], 2:[six.b('\x00\x00\x00\x09')]})

    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two'))
        self.assertEqual(self.packet[1], [six.b('one'), six.b('two')])

    def testDecodePacketWithTwoAttributes(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two'))
        self.assertEqual(self.packet[1], [six.b('one'), six.b('two')])

    def testDecodePacketWithVendorAttribute(self):
        self.packet.DecodePacket(
                six.b('\x01\x02\x00\x1b1234567890123456\x1a\x07value'))
        self.assertEqual(self.packet[26], [six.b('value')])

    def testEncodeKeyValues(self):
        self.assertEqual(self.packet._EncodeKeyValues(1, '1234'), (1, '1234'))

    def testEncodeKey(self):
        self.assertEqual(self.packet._EncodeKey(1), 1)

    def testAddAttribute(self):
        self.packet.AddAttribute('Test-String', '1')
        self.assertEqual(self.packet['Test-String'], ['1'])
        self.packet.AddAttribute('Test-String', '1')
        self.assertEqual(self.packet['Test-String'], ['1', '1'])
        self.packet.AddAttribute('Test-String', ['2', '3'])
        self.assertEqual(self.packet['Test-String'], ['1', '1', '2', '3'])

class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.AccessRequest)


class AuthPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer' : 10})
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
                six.b('\x01\x00\x00\x1401234567890ABCDE'))

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.authenticator is not None)

    def testRequestPacketCreatesID(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.id is not None)

    def testPwCryptEmptyPassword(self):
        self.assertEqual(self.packet.PwCrypt(''), six.b(''))

    def testPwCryptPassword(self):
        self.assertEqual(self.packet.PwCrypt('Simplon'),
                six.b('\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01'))

    def testPwCryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.PwCrypt(six.u(''))
        self.assertTrue(self.packet.authenticator is not None)

    def testPwDecryptEmptyPassword(self):
        self.assertEqual(self.packet.PwDecrypt(six.b('')), six.u(''))

    def testPwDecryptPassword(self):
        self.assertEqual(self.packet.PwDecrypt(
                six.b('\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01')),
                six.u('Simplon'))


class AuthPacketChapTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'chap'))
        # self.packet = packet.Packet(id=0, secret=six.b('secret'),
        #                             dict=self.dict)
        self.client = Client(server='localhost', secret=six.b('secret'),
                             dict=self.dict)

    def testVerifyChapPasswd(self):
        chap_id = b'9'
        chap_challenge = b'987654321'
        chap_password = chap_id + md5_constructor(
                chap_id + b'test_password' + chap_challenge).digest()
        pkt = self.client.CreateAuthPacket(
            code=packet.AccessChallenge,
            authenticator=b'ABCDEFG',
            User_Name='test_name',
            CHAP_Challenge=chap_challenge,
            CHAP_Password=chap_password
        )
        self.assertEqual(pkt['CHAP-Challenge'][0], chap_challenge)
        self.assertEqual(pkt['CHAP-Password'][0], chap_password)
        self.assertEqual(pkt.VerifyChapPasswd('test_password'), True)


class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.AccountingRequest)

    def testConstructorRawPacket(self):
        raw = six.b('\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c' \
                    '\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7')
        pkt = self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AcctPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer' : 10})
        self.assertEqual(reply.code, packet.AccountingResponse)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testVerifyAcctRequest(self):
        rawpacket = self.packet.RequestPacket()
        pkt = packet.AcctPacket(secret=six.b('secret'), packet=rawpacket)
        self.assertEqual(pkt.VerifyAcctRequest(), True)

        pkt.secret = six.b('different')
        self.assertEqual(pkt.VerifyAcctRequest(), False)
        pkt.secret = six.b('secret')

        pkt.raw_packet = six.b('X') + pkt.raw_packet[1:]
        self.assertEqual(pkt.VerifyAcctRequest(), False)

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
            six.b('\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f'))

    def testRequestPacketSetsId(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.id is not None)
