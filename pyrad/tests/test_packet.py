import hashlib
import hmac
import os
import signal
import struct
import unittest
import unittest.mock

from . import home

from collections import OrderedDict
from io import StringIO
from pyrad import packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary


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
        self.assertTrue(isinstance(pkt.secret, bytes))

    def testNamedConstructor(self):
        pkt = self.klass(code=26, id=38, secret=b'secret',
                         authenticator=b'authenticator',
                         dict='fakedict')
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, b'secret')
        self.assertEqual(pkt.authenticator, b'authenticator')
        self.assertEqual(pkt.dict, 'fakedict')

    def testConstructWithDictionary(self):
        pkt = self.klass(dict=self.dict)
        self.assertTrue(pkt.dict is self.dict)

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        self.assertFalse(getattr(pkt, 'fd', None) is marker)

    def testSecretMustBeBytestring(self):
        self.assertRaises(TypeError, self.klass, secret='secret')

    def testConstructorWithAttributes(self):
        pkt = self.klass(**{'Test-String': 'this works', 'dict': self.dict})
        self.assertEqual(pkt['Test-String'], ['this works'])

    def testConstructorWithTlvAttribute(self):
        pkt = self.klass(**{
            'Test-Tlv-Str': 'this works',
            'Test-Tlv-Int': 10,
            'dict': self.dict
        })
        self.assertEqual(
            pkt['Test-Tlv'],
            {'Test-Tlv-Str': ['this works'], 'Test-Tlv-Int': [10]}
        )


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.Packet(
            id=0, secret=b'secret',
            authenticator=b'01234567890ABCDEF', dict=self.dict)

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
                                                16 * b'\00')

        header = struct.pack('!BBH', packet.AccessAccept,
                             request.id, (20 + len(attributes)))

        # Calculate the Message-Authenticator and update the attribute
        hmac_constructor = hmac.new(request.secret, None, hashlib.md5)
        hmac_constructor.update(header + request.authenticator + attributes)
        updated_message_authenticator = hmac_constructor.digest()
        attributes = attributes.replace(b'\x00' * 16,
                                        updated_message_authenticator)

        # Calculate the response authenticator
        authenticator = hashlib.md5(header
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
        reply = self.packet.CreateReply(**{'Test-Integer': 10})
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testAttributeAccess(self):
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet['Test-Integer'], [10])
        self.assertEqual(self.packet[3], [b'\x00\x00\x00\x0a'])

        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet['Test-String'], ['dummy'])
        self.assertEqual(self.packet[1], [b'dummy'])

    def testAttributeValueAccess(self):
        self.packet['Test-Integer'] = 'Three'
        self.assertEqual(self.packet['Test-Integer'], ['Three'])
        self.assertEqual(self.packet[3], [b'\x00\x00\x00\x03'])

    def testVendorAttributeAccess(self):
        self.packet['Simplon-Number'] = 10
        self.assertEqual(self.packet['Simplon-Number'], [10])
        self.assertEqual(self.packet[(16, 1)], [b'\x00\x00\x00\x0a'])

        self.packet['Simplon-Number'] = 'Four'
        self.assertEqual(self.packet['Simplon-Number'], ['Four'])
        self.assertEqual(self.packet[(16, 1)], [b'\x00\x00\x00\x04'])

    def testRawAttributeAccess(self):
        marker = [b'']
        self.packet[1] = marker
        self.assertTrue(self.packet[1] is marker)
        self.packet[(16, 1)] = marker
        self.assertTrue(self.packet[(16, 1)] is marker)

    def testEncryptedAttributes(self):
        self.packet['Test-Encrypted-String'] = 'dummy'
        self.assertEqual(self.packet['Test-Encrypted-String'], ['dummy'])
        self.packet['Test-Encrypted-Integer'] = 10
        self.assertEqual(self.packet['Test-Encrypted-Integer'], [10])

    def testSaltCryptRoundTrip(self):
        # SaltDecrypt must invert SaltCrypt past the first 16-byte block. The
        # chaining used the ciphertext when encrypting but the plaintext when
        # decrypting, so anything over one block (MS-MPPE keys, long
        # Tunnel-Password) came back corrupt after byte 15.
        self.packet.request_authenticator = self.packet.authenticator
        for value in (b'x', b'0123456789abcde', bytes(range(32)), bytes(range(100))):
            self.assertEqual(
                self.packet.SaltDecrypt(self.packet.SaltCrypt(value)), value)

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
        self.assertTrue(isinstance(a, bytes))
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
                         (b'\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
                          b'\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7'))

    def testVerifyReply(self):
        reply = self.packet.CreateReply()
        self.assertEqual(self.packet.VerifyReply(reply), True)

        reply.id += 1
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.id = self.packet.id

        reply.secret = b'different'
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.secret = self.packet.secret

        reply.authenticator = b'X' * 16
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
            secret=b'secret',
            original_authenticator=self.packet.authenticator,
            original_code=self.packet.code))

        self.assertFalse(reply.verify_message_authenticator(
            secret=b'bad_secret',
            original_authenticator=self.packet.authenticator,
            original_code=self.packet.code))

        self.assertFalse(reply.verify_message_authenticator(
            secret=b'secret',
            original_authenticator=b'bad_authenticator',
            original_code=self.packet.code))

    def testVerifyMessageAuthenticatorDuplicateAttributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        self.assertTrue(reply.verify_message_authenticator(
            secret=b'secret',
            original_authenticator=self.packet.authenticator,
            original_code=packet.AccessRequest))

    def testPktEncodeAttribute(self):
        encode = self.packet._PktEncodeAttribute

        # Encode a normal attribute
        self.assertEqual(
                encode(1, b'value'),
                b'\x01\x07value')
        # Encode a vendor attribute
        self.assertEqual(
                encode((1, 2), b'value'),
                b'\x1a\x0d\x00\x00\x00\x01\x02\x07value')

    def testPktEncodeTlvAttribute(self):
        encode = self.packet._PktEncodeTlv

        # Encode a normal tlv attribute
        self.assertEqual(
                encode(4, {1: [b'value'], 2: [b'\x00\x00\x00\x02']}),
                b'\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02')

        # Encode a normal tlv attribute with several sub attribute instances
        self.assertEqual(
                encode(4, {1: [b'value', b'other'], 2: [b'\x00\x00\x00\x02']}),
                b'\x04\x16\x01\x07value\x02\x06\x00\x00\x00\x02\x01\x07other')
        # Encode a vendor tlv attribute
        self.assertEqual(
                encode((16, 3), {1: [b'value'], 2: [b'\x00\x00\x00\x02']}),
                b'\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02')

    def testPktEncodeLongTlvAttribute(self):
        encode = self.packet._PktEncodeTlv

        long_str = b'a' * 245
        # Encode a long tlv attribute - check it is split between AVPs
        self.assertEqual(
                encode(4, {1: [b'value', long_str], 2: [b'\x00\x00\x00\x02']}),
                b'\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02\x04\xf9\x01\xf7' + long_str)

        # Encode a long vendor tlv attribute
        first_avp = b'\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02'
        second_avp = b'\x1a\xff\x00\x00\x00\x10\x03\xf9\x01\xf7' + long_str
        self.assertEqual(
                encode((16, 3), {1: [b'value', long_str], 2: [b'\x00\x00\x00\x02']}),
                first_avp + second_avp)

    def testPktEncodeAttributes(self):
        self.packet[1] = [b'value']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x01\x07value')

        self.packet.clear()
        self.packet[(16, 2)] = [b'value']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x1a\x0d\x00\x00\x00\x10\x02\x07value')

        self.packet.clear()
        self.packet[1] = [b'one', b'two', b'three']
        self.assertEqual(self.packet._PktEncodeAttributes(),
                         b'\x01\x05one\x01\x05two\x01\x07three')

        self.packet.clear()
        self.packet[1] = [b'value']
        self.packet[(16, 2)] = [b'value']
        self.assertEqual(
                self.packet._PktEncodeAttributes(),
                b'\x01\x07value\x1a\x0d\x00\x00\x00\x10\x02\x07value')

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._PktDecodeVendorAttribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(b''), [(26, b'')])
        self.assertEqual(decode(b'12345'), [(26, b'12345')])

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(
                decode(b'\x00\x00\x00\x01\x02\x06value'),
                [(26, b'\x00\x00\x00\x01\x02\x06value')])

        # Proper RFC2865 recommended form
        self.assertEqual(
                decode(b'\x00\x00\x00\x10\x02\x07value'),
                [((16, 2), b'value')])

    def testPktDecodeTlvAttribute(self):
        decode = self.packet._PktDecodeTlvAttribute

        decode(4, b'\x01\x07value')
        self.assertEqual(self.packet[4], {1: [b'value']})

        # add another instance of the same sub attribute
        decode(4, b'\x01\x07other')
        self.assertEqual(self.packet[4], {1: [b'value', b'other']})

        # add a different sub attribute
        decode(4, b'\x02\x06\x00\x00\x00\x01')
        self.assertEqual(self.packet[4], {
            1: [b'value', b'other'],
            2: [b'\x00\x00\x00\x01']
        })

    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.DecodePacket(b'')
        except packet.PacketError as e:
            self.assertTrue('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.DecodePacket(b'\x00\x00\x00\x001234567890123456')
        except packet.PacketError as e:
            self.assertTrue('invalid length' in str(e))
        else:
            self.fail()

    def testDecodePacketShorterThanLength(self):
        self.assertRaises(packet.PacketError, self.packet.DecodePacket,
                          b'\x01\x02\x00\x1b1234567890123456\x01\x07valu')

    def testDecodePacketWithPadding(self):
        # RFC 2865 section 3: octets outside the range of the Length field
        # MUST be treated as padding and ignored on reception.
        raw = b'\x01\x02\x00\x1b1234567890123456\x01\x07value'
        self.packet.DecodePacket(raw + b'\x00\x00\x01\x07other')
        self.assertEqual(self.packet[1], [b'value'])
        self.assertEqual(self.packet.raw_packet, raw)

    def testConstructWithPaddedPacket(self):
        raw = b'\x01\x02\x00\x1b1234567890123456\x01\x07value'
        pkt = packet.Packet(dict=self.dict, packet=raw + 4 * b'\x00')
        self.assertEqual(pkt[1], [b'value'])
        self.assertEqual(pkt.raw_packet, raw)

    def testVerifyReplyDecodedWithoutRawReply(self):
        request = packet.AuthPacket(id=0, secret=b'secret',
                                    authenticator=b'0123456789ABCDEF',
                                    dict=self.dict)
        request.add_message_authenticator()
        request.RequestPacket()
        raw = request.CreateReply(**{'Test-String': 'test'}).ReplyPacket()
        received = request.CreateReply(packet=raw)
        ma = received[80][0]
        # the reply is verified with the bytes it was decoded from and not
        # modified
        self.assertTrue(request.VerifyReply(received))
        self.assertEqual(received[80][0], ma)
        self.assertEqual(received.authenticator, raw[4:20])
        self.assertEqual(received.raw_packet, raw)

    def testVerifyReplyDecodedWithoutRawReplyTampered(self):
        request = packet.AuthPacket(id=0, secret=b'secret',
                                    authenticator=b'0123456789ABCDEF',
                                    dict=self.dict)
        raw = request.CreateReply(**{'Test-String': 'test'}).ReplyPacket()
        received = request.CreateReply(packet=raw[:-1] + b'X')
        self.assertFalse(request.VerifyReply(received))

    def testVerifyReplyWithPadding(self):
        reply = self.packet.CreateReply(**{'Test-String': 'test'})
        raw = reply.ReplyPacket() + 4 * b'\x00'
        received = self.packet.CreateReply(packet=raw)
        self.assertTrue(self.packet.VerifyReply(received, raw))

    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.DecodePacket(b'\x00\x00\x24\x00' + (0x2400 - 4) * b'X')
        except packet.PacketError as e:
            self.assertTrue('too long' in str(e))
        else:
            self.fail()

    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.DecodePacket(
                    b'\x01\x02\x00\x151234567890123456\x00')
        except packet.PacketError as e:
            self.assertTrue('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithoutAttributes(self):
        self.packet.DecodePacket(b'\x01\x02\x00\x141234567890123456')
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, b'1234567890123456')
        self.assertEqual(self.packet.keys(), [])

    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.DecodePacket(
                    b'\x01\x02\x00\x161234567890123456\x00\x01')
        except packet.PacketError as e:
            self.assertTrue('too small' in str(e))
        else:
            self.fail()

    def testDecodePacketWithEmptyAttribute(self):
        self.packet.DecodePacket(
                b'\x01\x02\x00\x161234567890123456\x01\x02')
        self.assertEqual(self.packet[1], [b''])

    def testDecodePacketWithAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1b1234567890123456\x01\x07value')
        self.assertEqual(self.packet[1], [b'value'])

    def testDecodePacketWithTlvAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value')
        self.assertEqual(self.packet[4], {1: [b'value']})

    def testDecodePacketWithVendorTlvAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x231234567890123456\x1a\x0f\x00\x00\x00\x10\x03\x09\x01\x07value')
        self.assertEqual(self.packet[(16, 3)], {1: [b'value']})

    def testDecodePacketWithTlvAttributeWith2SubAttributes(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x231234567890123456\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x09')
        self.assertEqual(self.packet[4], {1: [b'value'], 2: [b'\x00\x00\x00\x09']})

    def testDecodePacketWithSplitTlvAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x251234567890123456\x04\x09\x01\x07value\x04\x09\x02\x06\x00\x00\x00\x09')
        self.assertEqual(self.packet[4], {1: [b'value'], 2: [b'\x00\x00\x00\x09']})

    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two')
        self.assertEqual(self.packet[1], [b'one', b'two'])

    def testDecodePacketWithTwoAttributes(self):
        self.packet.DecodePacket(
            b'\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two')
        self.assertEqual(self.packet[1], [b'one', b'two'])

    def testDecodePacketWithVendorAttribute(self):
        self.packet.DecodePacket(
                b'\x01\x02\x00\x1b1234567890123456\x1a\x07value')
        self.assertEqual(self.packet[26], [b'value'])

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

    def testAddAttributeWithNonStringKey(self):
        # e.g. swapped arguments: AddAttribute(pkt['Test-String'], 'Test-String') (#17)
        self.assertRaises(TypeError, self.packet.AddAttribute, ['1'], 'Test-String')
        self.assertRaises(TypeError, self.packet.AddAttribute, 1, '1')



class DecodeTimeout(BaseException):
    """Raised by the alarm handler; a BaseException so that broad
    ``except Exception`` blocks in the decoder cannot swallow it."""


@unittest.skipUnless(hasattr(signal, 'setitimer'), 'requires signal.setitimer')
class MalformedAttributeDecodeTests(unittest.TestCase):
    """Malformed (sub-)attribute lengths must not hang or crash the decoder."""

    def setUp(self):
        self.dict = Dictionary(os.path.join(home, 'data', 'full'))
        self.packet = packet.Packet(dict=self.dict)

        def timeout(signum, frame):
            raise DecodeTimeout('decoder did not terminate')
        self.old_handler = signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, 2)

    def tearDown(self):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old_handler)

    @staticmethod
    def _raw(attributes):
        return struct.pack('!BBH', 1, 2, 20 + len(attributes)) + \
            b'1234567890123456' + attributes

    def testVendorAttributeWithZeroLength(self):
        vsa = b'\x00\x00\x00\x10\x01\x00'
        self.packet.DecodePacket(self._raw(b'\x1a\x08' + vsa))
        self.assertEqual(self.packet[26], [vsa])

    def testVendorAttributeWithZeroLengthSecondSubAttribute(self):
        vsa = b'\x00\x00\x00\x10\x02\x07value\x01\x00'
        self.packet.DecodePacket(self._raw(b'\x1a\x0f' + vsa))
        self.assertEqual(self.packet[26], [vsa])

    def testVendorAttributeWithTooLongSubAttribute(self):
        vsa = b'\x00\x00\x00\x10\x02\x09value'
        self.packet.DecodePacket(self._raw(b'\x1a\x0d' + vsa))
        self.assertEqual(self.packet[26], [vsa])

    def testTlvAttributeWithZeroLength(self):
        self.assertRaises(packet.PacketError, self.packet.DecodePacket,
                          self._raw(b'\x04\x06\x01\x00zz'))

    def testTlvAttributeWithTruncatedSubAttribute(self):
        self.assertRaises(packet.PacketError, self.packet.DecodePacket,
                          self._raw(b'\x04\x03\x01'))

    def testTlvAttributeWithTooLongSubAttribute(self):
        self.assertRaises(packet.PacketError, self.packet.DecodePacket,
                          self._raw(b'\x04\x09\x01\x09value'))

    def testVendorTlvAttributeWithZeroLength(self):
        self.assertRaises(packet.PacketError, self.packet.DecodePacket,
                          self._raw(b'\x1a\x0c\x00\x00\x00\x10\x03\x06\x01\x00zz'))

    def testIntegerAttributeWithWrongLength(self):
        # the raw value is kept, only decoding it raises a ValueError (#13)
        self.packet.DecodePacket(self._raw(b'\x03\x04\x00\x01'))
        self.assertEqual(self.packet[3], [b'\x00\x01'])
        self.assertRaises(ValueError, self.packet.__getitem__, 'Test-Integer')

class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.AccessRequest)


class AuthPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(id=0, secret=b'secret',
                                        authenticator=b'01234567890ABCDEF',
                                        dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer': 10})
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
                         b'\x01\x00\x00\x1401234567890ABCDE')

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.authenticator is not None)

    def testRequestPacketCreatesID(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.id is not None)

    def testPwCryptEmptyPassword(self):
        # RFC 2865 section 5.2: padded with nulls to 16 octets
        encrypted = self.packet.PwCrypt('')
        self.assertEqual(len(encrypted), 16)
        self.assertEqual(encrypted, self.packet.PwCrypt(16 * b'\x00'))
        self.assertEqual(self.packet.PwDecrypt(encrypted), '')

    def testPwCryptMaximumLength(self):
        encrypted = self.packet.PwCrypt(128 * 'x')
        self.assertEqual(len(encrypted), 128)
        self.assertEqual(self.packet.PwDecrypt(encrypted), 128 * 'x')

    def testPwCryptTooLong(self):
        # RFC 2865 section 5.2: the password is at most 128 octets
        self.assertRaises(ValueError, self.packet.PwCrypt, 129 * 'x')
        self.assertRaises(ValueError, self.packet.PwCrypt, 65 * '\xe9')

    def testPwCryptPassword(self):
        self.assertEqual(self.packet.PwCrypt('Simplon'),
                         b'\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01')

    def testPwCryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.PwCrypt('')
        self.assertTrue(self.packet.authenticator is not None)

    def testPwDecryptEmptyPassword(self):
        self.assertEqual(self.packet.PwDecrypt(b''), '')

    def testPwDecryptPassword(self):
        self.assertEqual(self.packet.PwDecrypt(
                b'\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01'),
                'Simplon')

    def testPwDecryptNamedAttribute(self):
        # The encrypted value is not valid UTF-8 and must survive the
        # string decoding of the named attribute access (#232).
        dictionary = Dictionary(StringIO('ATTRIBUTE User-Password 2 string\n'))
        request = packet.AuthPacket(secret=b'secret', dict=dictionary,
                                    authenticator=b'0123456789ABCDEF')
        request['User-Password'] = request.PwCrypt('Simplon')
        pkt = packet.AuthPacket(packet=request.RequestPacket(),
                                secret=b'secret', dict=dictionary)
        self.assertEqual(pkt.PwDecrypt(pkt['User-Password'][0]), 'Simplon')

    def testPwDecryptUtf8String(self):
        # An encrypted value which is valid UTF-8 is decoded to str by the
        # named attribute access and must be converted back losslessly (#192).
        encrypted = ('\xe9' * 8).encode('utf-8')
        self.assertEqual(self.packet.PwDecrypt(encrypted.decode('utf-8')),
                         self.packet.PwDecrypt(encrypted))


class AuthPacketChapTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'chap'))
        # self.packet = packet.Packet(id=0, secret=b'secret',
        #                             dict=self.dict)
        self.client = Client(server='localhost', secret=b'secret',
                             dict=self.dict)

    def testVerifyChapPasswd(self):
        chap_id = b'9'
        chap_challenge = b'987654321'
        chap_password = chap_id + hashlib.md5(
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

    def testVerifyChapPasswdWithoutChapPassword(self):
        pkt = self.client.CreateAuthPacket(authenticator=16 * b'A',
                                           User_Name='test_name')
        self.assertFalse(pkt.VerifyChapPasswd('test_password'))

    def testVerifyChapPasswdWrongPassword(self):
        chap_id = b'9'
        chap_password = chap_id + hashlib.md5(
                chap_id + b'test_password' + 16 * b'A').digest()
        pkt = self.client.CreateAuthPacket(authenticator=16 * b'A',
                                           CHAP_Password=chap_password)
        self.assertTrue(pkt.VerifyChapPasswd(b'test_password'))
        self.assertFalse(pkt.VerifyChapPasswd(b'other_password'))

    def testVerifyChapPasswdUsesConstantTimeComparison(self):
        chap_id = b'9'
        chap_password = chap_id + hashlib.md5(
                chap_id + b'test_password' + 16 * b'A').digest()
        pkt = self.client.CreateAuthPacket(authenticator=16 * b'A',
                                           CHAP_Password=chap_password)
        calls = []
        compare_digest = hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return compare_digest(a, b)

        with unittest.mock.patch('pyrad.packet.hmac.compare_digest', spy):
            self.assertTrue(pkt.VerifyChapPasswd('test_password'))
        self.assertEqual(len(calls), 1)


class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.AccountingRequest)

    def testConstructorRawPacket(self):
        raw = (b'\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
               b'\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7')
        pkt = self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AcctPacket(id=0, secret=b'secret',
                                        authenticator=b'01234567890ABCDEF',
                                        dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(**{'Test-Integer': 10})
        self.assertEqual(reply.code, packet.AccountingResponse)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testVerifyAcctRequest(self):
        rawpacket = self.packet.RequestPacket()
        pkt = packet.AcctPacket(secret=b'secret', packet=rawpacket)
        self.assertEqual(pkt.VerifyAcctRequest(), True)

        pkt.secret = b'different'
        self.assertEqual(pkt.VerifyAcctRequest(), False)
        pkt.secret = b'secret'

        pkt.raw_packet = b'X' + pkt.raw_packet[1:]
        self.assertEqual(pkt.VerifyAcctRequest(), False)

    def testVerifyAcctRequestWithPadding(self):
        self.packet['Test-String'] = 'test'
        self.packet.add_message_authenticator()
        rawpacket = self.packet.RequestPacket() + 4 * b'\x00'
        pkt = packet.AcctPacket(secret=b'secret', dict=self.dict,
                                packet=rawpacket)
        self.assertEqual(pkt['Test-String'], ['test'])
        self.assertTrue(pkt.VerifyAcctRequest())
        self.assertTrue(pkt.verify_message_authenticator())

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
                         b'\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f')

    def testRequestPacketSetsId(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.assertTrue(self.packet.id is not None)

    def testRealisticUnknownAttributes(self):
        """ Test a realistic Accounting Packet from raw
        User-Name: [u'user@example.com']
        NAS-IP-Address: ['1.2.3.4']
        Service-Type: ['Framed-User']
        Framed-Protocol: ['NAS-Prompt-User']
        Framed-IP-Address: ['1.2.3.4']
        Acct-Status-Type: ['Interim-Update']
        Acct-Delay-Time: [0]
        Acct-Input-Octets: [1290826858]
        Acct-Output-Octets: [3551101035]
        Acct-Session-Id: [u'90dbd65a18b0a6c']
        Acct-Authentic: ['RADIUS']
        Acct-Session-Time: [769500]
        Acct-Input-Packets: [7403861]
        Acct-Output-Packets: [10928170]
        Acct-Link-Count: [1]
        Acct-Input-Gigawords: [0]
        Acct-Output-Gigawords: [2]
        Event-Timestamp: [1554155989]
        # vendor specific
        NAS-Port-Type: ['Virtual']
        (26, 594, 1): [u'UNKNOWN_PRODUCT']
        # implementation specific fields
        224: ['24P\x10\x00\x22\x96\xc9']
        228: ['\xfe\x99\xd0P']
        """
        # path = os.path.join(home, 'tests', 'data')
        path = os.path.join(home, 'data')
        dictObj = Dictionary(os.path.join(path, 'realistic'))
        raw = b'\x04\x8e\x00\xc4\xb2\xf8z\xdb\xac\xfd9l\x9dI?E\x8c%\xe9'\
              b'\xf5\x01\x12user@example.com\x04\x06\x01\x02\x03\x04\x06\x06'\
              b'\x00\x00\x00\x02\x07\x06\x00\x00\x00\x07\x08\x06\x01\x02\x03'\
              b'\x04(\x06\x00\x00\x00\x03)\x06\x00\x00\x00\x00*\x06L\xf0tj+'\
              b'\x06\xd3\xa9\x80k,\x1190dbd65a18b0a6c-\x06\x00\x00\x00\x01.'\
              b'\x06\x00\x0b\xbd\xdc/\x06\x00p\xf9U0\x06\x00\xa6\xc0*3\x06'\
              b'\x00\x00\x00\x014\x06\x00\x00\x00\x005\x06\x00\x00\x00\x027'\
              b'\x06\\\xa2\x89\xd5=\x06\x00\x00\x00\x05\x1a\x17\x00\x00\x02R'\
              b'\x01\x11UNKNOWN_PRODUCT\xe0\n24P\x10\x00\x22\x96\xc9\xe4\x06'\
              b'\xfe\x99\xd0P'

        pkt = packet.AcctPacket(dict=dictObj, packet=raw)
        self.assertEqual(pkt.raw_packet, raw)

        # Test verifies packet parses correctly
        self.assertEqual(pkt.code, packet.AccountingRequest)  # 4
        self.assertEqual(pkt['User-Name'], ['user@example.com'])
        self.assertEqual(pkt['NAS-IP-Address'], ['1.2.3.4'])
        self.assertEqual(pkt['Acct-Status-Type'], ['Interim-Update'])
        self.assertEqual(pkt['Acct-Session-Id'], ['90dbd65a18b0a6c'])
        self.assertEqual(pkt['Acct-Authentic'], ['RADIUS'])

        # Unknown attributes preserved
        self.assertEqual(pkt[224][0], b'24P\x10\x00\x22\x96\xc9')
        self.assertEqual(pkt[228][0], b'\xfe\x99\xd0P')

        # Vendor unknown preserved
        self.assertEqual(pkt[(594, 1)], [b'UNKNOWN_PRODUCT'])

        raw_no_authenticator = raw[:4] + b"\x00" * 16 + raw[20:]
        rebuilt = pkt.RequestPacket()
        rebuilt_no_authenticator = rebuilt[:4] + b"\x00" * 16 + rebuilt[20:]

        self.assertEqual(raw_no_authenticator, rebuilt_no_authenticator)


class PacketEdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.dict = Dictionary(os.path.join(home, 'data', 'full'))

    def testAuthenticatorMustBeBytes(self):
        self.assertRaises(TypeError, packet.Packet, authenticator='0123456789abcdef')

    def testAddMessageAuthenticatorCreatesIdAndAuthenticator(self):
        pkt = packet.AuthPacket(secret=b'secret', dict=self.dict)
        pkt.id = None
        pkt.add_message_authenticator()
        self.assertIsNotNone(pkt.id)
        self.assertIsNotNone(pkt.authenticator)
        self.assertTrue(pkt.get_message_authenticator())
        self.assertEqual(len(pkt[80][0]), 16)

    def testMessageAuthenticatorWithoutAuthenticator(self):
        pkt = packet.Packet(code=packet.AccessAccept, secret=b'secret', dict=self.dict)
        pkt.add_message_authenticator()
        self.assertRaises(Exception, pkt._refresh_message_authenticator)

    def testVerifyMessageAuthenticatorErrors(self):
        pkt = packet.AuthPacket(secret=b'secret', dict=self.dict)
        self.assertRaises(Exception, pkt.verify_message_authenticator)
        pkt.add_message_authenticator()
        pkt.secret = None
        self.assertRaises(Exception, pkt.verify_message_authenticator)

    def testTaggedAttributes(self):
        # RFC 2868 section 3: the tag replaces the first octet of integers
        dictionary = Dictionary(StringIO(
            'ATTRIBUTE Tunnel-Type 64 integer has_tag\n'
            'ATTRIBUTE Tunnel-Private-Group-Id 81 string has_tag\n'))
        pkt = packet.Packet(dict=dictionary)
        pkt['Tunnel-Type:1'] = 3
        pkt['Tunnel-Private-Group-Id:2'] = 'vlan'
        self.assertEqual(pkt[64], [b'\x01\x00\x00\x03'])
        self.assertEqual(pkt[81], [b'\x02vlan'])

    def tagged_dictionary(self):
        return Dictionary(StringIO(
            'ATTRIBUTE Tunnel-Type 64 integer has_tag\n'
            'ATTRIBUTE Tunnel-Password 69 string has_tag,encrypt=2\n'
            'ATTRIBUTE Tunnel-Private-Group-Id 81 string has_tag\n'
            'VALUE Tunnel-Type VLAN 13\n'))

    def testTaggedAttributesRoundTrip(self):
        dictionary = self.tagged_dictionary()
        request = packet.AuthPacket(secret=b'secret', dict=dictionary,
                                    authenticator=b'0123456789ABCDEF')
        reply = request.CreateReply()
        reply.AddAttribute('Tunnel-Type:1', 'VLAN')
        reply.AddAttribute('Tunnel-Type:2', 'VLAN')
        reply.AddAttribute('Tunnel-Private-Group-Id:1', '100')
        reply.AddAttribute('Tunnel-Private-Group-Id:2', '200')
        reply.AddAttribute('Tunnel-Password:1', 'first-tunnel-password')
        reply.AddAttribute('Tunnel-Password:2', 'second')

        decoded = packet.Packet(packet=reply.ReplyPacket(), secret=b'secret',
                                dict=dictionary)
        decoded.request_authenticator = request.authenticator
        self.assertEqual(decoded['Tunnel-Type'], ['VLAN', 'VLAN'])
        self.assertEqual(decoded['Tunnel-Type:2'], ['VLAN'])
        self.assertEqual(decoded['Tunnel-Private-Group-Id'], ['100', '200'])
        self.assertEqual(decoded['Tunnel-Private-Group-Id:1'], ['100'])
        self.assertEqual(decoded['Tunnel-Private-Group-Id:2'], ['200'])
        self.assertEqual(decoded['Tunnel-Password:1'], ['first-tunnel-password'])
        self.assertEqual(decoded['Tunnel-Password:2'], ['second'])
        self.assertTrue('Tunnel-Type:1' in decoded)
        self.assertFalse('Tunnel-Type:3' in decoded)
        self.assertRaises(KeyError, decoded.__getitem__, 'Tunnel-Type:3')
        self.assertEqual(decoded.get('Tunnel-Type:3', []), [])

    def testUntaggedAttributes(self):
        dictionary = self.tagged_dictionary()
        pkt = packet.AuthPacket(secret=b'secret', dict=dictionary,
                                authenticator=b'0123456789ABCDEF')
        pkt['Tunnel-Type'] = 'VLAN'
        pkt['Tunnel-Private-Group-Id'] = 'vlan'
        pkt['Tunnel-Password'] = 'password'
        # RFC 2868 section 3.5: Tunnel-Password always has a tag
        self.assertEqual(pkt[69][0][:1], b'\x00')
        self.assertEqual(len(pkt[69][0]), 1 + 2 + 16)
        self.assertEqual(pkt['Tunnel-Type'], ['VLAN'])
        self.assertEqual(pkt['Tunnel-Type:0'], ['VLAN'])
        self.assertEqual(pkt['Tunnel-Private-Group-Id'], ['vlan'])
        self.assertEqual(pkt['Tunnel-Password'], ['password'])
        # a first octet above 0x1F is part of the value, not a tag
        pkt[81] = [b'\x1fvlan', b' vlan']
        self.assertEqual(pkt['Tunnel-Private-Group-Id'], ['vlan', ' vlan'])

    def testInvalidTag(self):
        pkt = packet.Packet(dict=self.tagged_dictionary())
        self.assertRaises(ValueError, pkt.__setitem__, 'Tunnel-Type:32', 'VLAN')

    def testInvalidSaltEncryptedValue(self):
        pkt = packet.Packet(secret=b'secret', dict=self.tagged_dictionary(),
                            authenticator=b'0123456789ABCDEF')
        pkt[69] = [b'\x01\x80\x00short']
        self.assertRaises(packet.PacketError, pkt.__getitem__, 'Tunnel-Password')

    def testGetDefault(self):
        pkt = packet.Packet(dict=self.dict)
        self.assertEqual(pkt.get('Test-String', 'default'), 'default')

    def testTlvAttributeRoundTrip(self):
        pkt = packet.AuthPacket(secret=b'secret', dict=self.dict,
                                authenticator=b'0123456789ABCDEF',
                                **{'Test-Tlv-Str': 'text', 'Test-Tlv-Int': 10})
        decoded = packet.AuthPacket(packet=pkt.RequestPacket(), secret=b'secret',
                                    dict=self.dict)
        self.assertEqual(decoded['Test-Tlv'],
                         {'Test-Tlv-Str': ['text'], 'Test-Tlv-Int': [10]})

    def testEapMd5MessageAuthenticator(self):
        pkt = packet.AuthPacket(secret=b'secret', dict=self.dict, auth_type='eap-md5',
                                authenticator=b'0123456789ABCDEF')
        pkt['Test-String'] = 'eap'
        received = packet.AuthPacket(packet=pkt.RequestPacket(), secret=b'secret',
                                     dict=self.dict)
        self.assertTrue(received.verify_message_authenticator())

    def testPwDecryptBytearray(self):
        pkt = packet.AuthPacket(secret=b'secret', authenticator=b'0123456789ABCDEF')
        self.assertEqual(pkt.PwDecrypt(bytearray(pkt.PwCrypt('password'))), 'password')

    def testSaltCryptString(self):
        pkt = packet.AuthPacket(secret=b'secret', authenticator=b'0123456789ABCDEF')
        self.assertEqual(pkt.SaltDecrypt(pkt.SaltCrypt('password')), b'password')

    def testVerifyChapPasswdInvalidLength(self):
        pkt = packet.AuthPacket(secret=b'secret', dict=self.dict)
        pkt[3] = [b'\x01short']
        self.assertFalse(pkt.VerifyChapPasswd('password'))
        self.assertIsNotNone(pkt.authenticator)

    def testRequestPacketCreatesId(self):
        for klass in (packet.AcctPacket, packet.CoAPacket):
            pkt = klass(secret=b'secret', dict=self.dict)
            pkt.id = None
            pkt.RequestPacket()
            self.assertIsNotNone(pkt.id)

    def testZeroMessageAuthenticator(self):
        zero = packet.Packet._zero_message_authenticator
        ma = b'\x50\x12' + b'M' * 16
        self.assertEqual(zero(b'\x01\x05abc' + ma + b'\x01\x03d'),
                         b'\x01\x05abc\x50\x12' + 16 * b'\x00' + b'\x01\x03d')
        # without a (parseable) Message-Authenticator attr is unchanged
        self.assertEqual(zero(b'\x01\x05abc'), b'\x01\x05abc')
        self.assertEqual(zero(b'\x01\x00' + ma), b'\x01\x00' + ma)

    def testVendorAttributeWithMultipleSubAttributes(self):
        pkt = packet.Packet(dict=self.dict)
        vsa = b'\x00\x00\x00\x10\x01\x06\x00\x00\x00\x02\x02\x07value'
        pkt.DecodePacket(struct.pack('!BBH', 1, 2, 22 + len(vsa)) + 16 * b'\x00' +
                         b'\x1a' + struct.pack('B', 2 + len(vsa)) + vsa)
        self.assertEqual(pkt['Simplon-Number'], ['Two'])
        self.assertEqual(pkt['Simplon-String'], ['value'])

    def _decode(self, attributes, code=packet.AccessRequest):
        pkt = packet.Packet(dict=self.dict)
        pkt.DecodePacket(struct.pack('!BBH', code, 2, 20 + len(attributes)) +
                         16 * b'\x00' + attributes)
        return pkt

    def testVendorTlvAfterOtherSubAttribute(self):
        number = b'\x01\x06\x00\x00\x00\x02'
        tlv = b'\x03\x07\x01\x05abc'
        vsa = b'\x00\x00\x00\x10' + number + tlv
        pkt = self._decode(b'\x1a' + struct.pack('B', 2 + len(vsa)) + vsa)
        self.assertEqual(pkt['Simplon-Number'], ['Two'])
        self.assertEqual(pkt['Simplon-Tlv'], {'Simplon-Tlv-Str': ['abc']})

    def testVendorTlvInSeveralVendorAttributes(self):
        # used to raise AttributeError, which stopped the blocking server
        first = b'\x00\x00\x00\x10\x03\x07\x01\x05abc'
        second = b'\x00\x00\x00\x10\x01\x06\x00\x00\x00\x02\x03\x07\x01\x05def'
        pkt = self._decode(b'\x1a' + struct.pack('B', 2 + len(first)) + first +
                           b'\x1a' + struct.pack('B', 2 + len(second)) + second)
        self.assertEqual(pkt['Simplon-Tlv'], {'Simplon-Tlv-Str': ['abc', 'def']})
        self.assertEqual(pkt['Simplon-Number'], ['Two'])

    def testEmptyTlv(self):
        pkt = self._decode(b'\x04\x02')
        self.assertEqual(pkt['Test-Tlv'], {})
        self.assertEqual(pkt._PktEncodeAttributes(), b'\x04\x02')

    def testTlvUndefinedSubAttribute(self):
        pkt = self._decode(b'\x04\x0a\x01\x05abc\x09\x03A')
        self.assertEqual(pkt['Test-Tlv'], {'Test-Tlv-Str': ['abc'], 9: [b'A']})

    def testVerifyReplyWithEmptyTlv(self):
        # a forged reply used to raise ValueError instead of failing
        request = packet.AuthPacket(secret=b'secret', dict=self.dict)
        request.RequestPacket()
        raw = (struct.pack('!BBH', packet.AccessAccept, request.id, 22) +
               16 * b'\x00' + b'\x04\x02')
        reply = packet.Packet(secret=b'secret', dict=self.dict, packet=raw)
        self.assertFalse(request.VerifyReply(reply, raw))

    def testPwDecryptInvalidLength(self):
        pkt = packet.AuthPacket(secret=b'secret', authenticator=b'0123456789ABCDEF')
        for length in (5, 17, 31):
            self.assertRaises(packet.PacketError, pkt.PwDecrypt, length * b'x')
        self.assertEqual(pkt.PwDecrypt(pkt.PwCrypt('x' * 17)), 'x' * 17)

    def testVendorAttributeWithoutDictionary(self):
        pkt = packet.Packet()
        vsa = b'\x00\x00\x00\x10\x01\x06\x00\x00\x00\x02'
        pkt.DecodePacket(struct.pack('!BBH', 1, 2, 22 + len(vsa)) + 16 * b'\x00' +
                         b'\x1a' + struct.pack('B', 2 + len(vsa)) + vsa)
        self.assertEqual(pkt[26], [vsa])

    def testSaltCryptWithoutAuthenticator(self):
        pkt = packet.Packet(secret=b'secret')
        encrypted = pkt.SaltCrypt('password')
        self.assertEqual(pkt.authenticator, 16 * b'\x00')
        self.assertEqual(pkt.SaltDecrypt(encrypted), b'password')

    def testSaltCryptRequestUsesZeroVector(self):
        for (klass, code) in ((packet.AcctPacket, packet.AccountingRequest),
                              (packet.CoAPacket, packet.CoARequest),
                              (packet.CoAPacket, packet.DisconnectRequest)):
            pkt = klass(code=code, secret=b'secret', dict=self.dict)
            encrypted = pkt.SaltCrypt('password')
            key = hashlib.md5(b'secret' + 16 * b'\x00' + encrypted[:2]).digest()
            plain = bytes(a ^ b for (a, b) in zip(key, encrypted[2:18]))
            self.assertEqual(plain[:9], b'\x08password')

    def testSaltCryptRequestRoundTrip(self):
        for (klass, code, verify) in (
                (packet.AcctPacket, packet.AccountingRequest, 'VerifyAcctRequest'),
                (packet.CoAPacket, packet.CoARequest, 'VerifyCoARequest'),
                (packet.CoAPacket, packet.DisconnectRequest, 'VerifyCoARequest')):
            pkt = klass(code=code, secret=b'secret', dict=self.dict)
            pkt['Test-Encrypted-String'] = 'first'
            pkt.RequestPacket()
            # added after the Request Authenticator was calculated
            pkt['Test-Encrypted-Octets'] = b'second'
            received = klass(secret=b'secret', dict=self.dict,
                             packet=pkt.RequestPacket())
            self.assertTrue(getattr(received, verify)())
            self.assertEqual(received['Test-Encrypted-String'], ['first'])
            self.assertEqual(received['Test-Encrypted-Octets'], [b'second'])

    def testSaltCryptAccessRequestAuthenticator(self):
        authenticators = set()
        passwords = set()
        for _ in range(2):
            pkt = packet.AuthPacket(secret=b'secret', dict=self.dict)
            pkt['Test-Encrypted-String'] = 'dummy'
            pkt['Test-String'] = pkt.PwCrypt('password')
            raw = pkt.RequestPacket()
            self.assertNotEqual(pkt.authenticator, 16 * b'\x00')
            authenticators.add(pkt.authenticator)
            passwords.add(pkt['Test-String'][0])
            received = packet.AuthPacket(secret=b'secret', dict=self.dict,
                                         packet=raw)
            self.assertEqual(received['Test-Encrypted-String'], ['dummy'])
        self.assertEqual(len(authenticators), 2)
        self.assertEqual(len(passwords), 2)

    def testVerifyAuthRequest(self):
        attr = b'\x01\x07alice'
        header = struct.pack('!BBH', packet.AccessRequest, 1, 20 + len(attr))
        authenticator = hashlib.md5(header + 16 * b'\x00' + attr + b'secret').digest()
        pkt = packet.AuthPacket(secret=b'secret', dict=self.dict,
                                packet=header + authenticator + attr)
        self.assertTrue(pkt.VerifyAuthRequest())
        pkt.secret = b'different'
        self.assertFalse(pkt.VerifyAuthRequest())

    def testAcctRequestPacketWithMessageAuthenticator(self):
        pkt = packet.AcctPacket(secret=b'secret', dict=self.dict)
        pkt.add_message_authenticator()
        received = packet.AcctPacket(packet=pkt.RequestPacket(), secret=b'secret',
                                     dict=self.dict)
        self.assertTrue(received.VerifyAcctRequest())
        self.assertTrue(received.verify_message_authenticator())

    def testEncodeAttributeTooLong(self):
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        pkt[1] = [253 * b'x']
        self.assertEqual(len(pkt.ReplyPacket()), 20 + 255)
        pkt[1] = [254 * b'x']
        with self.assertRaisesRegex(ValueError, 'too long'):
            pkt.ReplyPacket()

    def testEncodeVendorAttributeTooLong(self):
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        # 26, length, 4 octets vendor id, type, length, value
        pkt[(16, 2)] = [247 * b'x']
        self.assertEqual(len(pkt.ReplyPacket()), 20 + 255)
        pkt[(16, 2)] = [248 * b'x']
        with self.assertRaisesRegex(ValueError, 'too long'):
            pkt.ReplyPacket()

    def testEncodeTlvAttributeTooLong(self):
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        pkt.AddAttribute('Test-Tlv-Str', 251 * 'x')
        self.assertEqual(pkt.ReplyPacket()[20:], b'\x04\xff\x01\xfd' + 251 * b'x')
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        pkt.AddAttribute('Test-Tlv-Str', 252 * 'x')
        with self.assertRaisesRegex(ValueError, 'too long'):
            pkt.ReplyPacket()

    def testEncodeVendorTlvAttributeTooLong(self):
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        pkt.AddAttribute('Simplon-Tlv-Str', 245 * 'x')
        self.assertEqual(pkt.ReplyPacket()[20:],
                         b'\x1a\xff\x00\x00\x00\x10\x03\xf9\x01\xf7' + 245 * b'x')
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        pkt.AddAttribute('Simplon-Tlv-Str', 246 * 'x')
        with self.assertRaisesRegex(ValueError, 'too long'):
            pkt.ReplyPacket()

    def testSaltCryptTooLong(self):
        pkt = packet.Packet(dict=self.dict, secret=b'secret',
                            authenticator=16 * b'\x00')
        self.assertRaises(ValueError, pkt.SaltCrypt, 256 * 'x')

    def testTunnelPasswordTooLong(self):
        dictionary = Dictionary(StringIO(
            'ATTRIBUTE Tunnel-Password 69 string has_tag,encrypt=2\n'))
        request = packet.AuthPacket(secret=b'secret', dict=dictionary,
                                    authenticator=b'0123456789ABCDEF')
        reply = request.CreateReply()
        reply.AddAttribute('Tunnel-Password:1', 240 * 'x')
        with self.assertRaisesRegex(ValueError, 'too long'):
            reply.ReplyPacket()
