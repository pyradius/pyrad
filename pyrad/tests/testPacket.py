import os
import unittest
import six
from pyrad import packet
from pyrad.tests import home
from pyrad.dictionary import Dictionary


class UtilityTests(unittest.TestCase):

    def testGenerateID(self):
        id = packet.create_id()
        self.failUnless(isinstance(id, int))
        newid = packet.create_id()
        self.assertNotEqual(id, newid)


class PacketConstructionTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'simple'))

    def testBasicConstructor(self):
        pkt = self.klass()
        self.failUnless(isinstance(pkt.code, int))
        self.failUnless(isinstance(pkt.id, int))
        self.failUnless(isinstance(pkt.secret, six.binary_type))

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
        self.failUnless(pkt.dict is self.dict)

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        self.failIf(getattr(pkt, 'fd', None) is marker)

    def testSecretMustBeBytestring(self):
        self.assertRaises(TypeError, self.klass, secret=six.u('secret'))

    def testConstructorWithAttributes(self):
        pkt = self.klass(dict=self.dict, Test_String='this works')
        self.assertEqual(pkt['Test-String'], ['this works'])


class PacketTests(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.Packet(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testcreate_reply(self):
        reply = self.packet.create_reply(Test_Integer=10)
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
        self.failUnless(self.packet[1] is marker)
        self.packet[(16, 1)] = marker
        self.failUnless(self.packet[(16, 1)] is marker)

    def testHasKey(self):
        self.assertEqual('Test-String' in self.packet, False)
        self.assertEqual('Test-String' in self.packet, False)
        self.packet['Test-String'] = 'dummy'
        self.assertEqual('Test-String' in self.packet, True)
        self.assertEqual(1 in self.packet, True)
        self.assertEqual(1 in self.packet, True)

    def testHasKeyWithUnknownKey(self):
        self.assertEqual('Unknown-Attribute' in self.packet, False)
        self.assertEqual('Unknown-Attribute' in self.packet, False)

    def testDelItem(self):
        self.packet['Test-String'] = 'dummy'
        del self.packet['Test-String']
        self.assertEqual('Test-String' in self.packet, False)
        self.packet['Test-String'] = 'dummy'
        del self.packet[1]
        self.assertEqual('Test-String' in self.packet, False)

    def testKeys(self):
        self.assertEqual(self.packet.keys(), [])
        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet.keys(), ['Test-String'])
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet.keys(), ['Test-String', 'Test-Integer'])
        dict.__setitem__(self.packet, 12345, None)
        self.assertEqual(self.packet.keys(),
                        ['Test-String', 'Test-Integer', 12345])

    def testcreate_authenticator(self):
        a = packet.Packet.create_authenticator()
        self.failUnless(isinstance(a, six.binary_type))
        self.assertEqual(len(a), 16)

        b = packet.Packet.create_authenticator()
        self.assertNotEqual(a, b)

    def testGenerateID(self):
        id = self.packet.create_id()
        self.failUnless(isinstance(id, int))
        newid = self.packet.create_id()
        self.assertNotEqual(id, newid)

    def testreply_packet(self):
        reply = self.packet.reply_packet()
        self.assertEqual(reply,
                six.b('\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
                      '\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7'))

    def testverify_reply(self):
        reply = self.packet.create_reply()
        self.assertEqual(self.packet.verify_reply(reply), True)

        reply.id += 1
        self.assertEqual(self.packet.verify_reply(reply), False)
        reply.id = self.packet.id

        reply.secret = six.b('different')
        self.assertEqual(self.packet.verify_reply(reply), False)
        reply.secret = self.packet.secret

        reply.authenticator = six.b('X') * 16
        self.assertEqual(self.packet.verify_reply(reply), False)
        reply.authenticator = self.packet.authenticator

    def testPktEncodeAttribute(self):
        encode = self.packet._pkt_encode_attribute

        # Encode a normal attribute
        self.assertEqual(
            encode(1, six.b('value')),
            six.b('\x01\x07value'))
        # Encode a vendor attribute
        self.assertEqual(
            encode((1, 2), six.b('value')),
            six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value'))

    def testPktEncodeAttributes(self):
        self.packet[1] = [six.b('value')]
        self.assertEqual(self.packet._pkt_encode_attributes(),
                six.b('\x01\x07value'))

        self.packet.clear()
        self.packet[(1, 2)] = [six.b('value')]
        self.assertEqual(self.packet._pkt_encode_attributes(),
                six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value'))

        self.packet.clear()
        self.packet[1] = [six.b('one'), six.b('two'), six.b('three')]
        self.assertEqual(self.packet._pkt_encode_attributes(),
                six.b('\x01\x05one\x01\x05two\x01\x07three'))

        self.packet.clear()
        self.packet[1] = [six.b('value')]
        self.packet[(1, 2)] = [six.b('value')]
        self.assertEqual(
            self.packet._pkt_encode_attributes(),
            six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value\x01\x07value'))

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._pkt_decode_vendor_attribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(six.b('')), [(26, six.b(''))])
        self.assertEqual(decode(six.b('12345')), [(26, six.b('12345'))])

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(
            decode(six.b('\x00\x00\x00\x01\x02\x06value')),
            [(26, six.b('\x00\x00\x00\x01\x02\x06value'))])

        # Proper RFC2865 recommended form
        self.assertEqual(
            decode(six.b('\x00\x00\x00\x01\x02\x07value')),
            [((1, 2), six.b('value'))])

    def testdecode_packetWithEmptyPacket(self):
        try:
            self.packet.decode_packet(six.b(''))
        except packet.PacketError as e:
            self.failUnless('header is corrupt' in str(e))
        else:
            self.fail()

    def testdecode_packetWithInvalidLength(self):
        try:
            self.packet.decode_packet(six.b('\x00\x00\x00\x001234567890123456'))
        except packet.PacketError as e:
            self.failUnless('invalid length' in str(e))
        else:
            self.fail()

    def testdecode_packetWithTooBigPacket(self):
        try:
            self.packet.decode_packet(
                six.b(
                    '\x00\x00\x24\x00') + (
                        0x2400 - 4) * six.b(
                            'X'))
        except packet.PacketError as e:
            self.failUnless('too long' in str(e))
        else:
            self.fail()

    def testdecode_packetWithPartialAttributes(self):
        try:
            self.packet.decode_packet(
                    six.b('\x01\x02\x00\x151234567890123456\x00'))
        except packet.PacketError as e:
            self.failUnless('header is corrupt' in str(e))
        else:
            self.fail()

    def testdecode_packetWithoutAttributes(self):
        self.packet.decode_packet(six.b('\x01\x02\x00\x141234567890123456'))
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, six.b('1234567890123456'))
        self.assertEqual(self.packet.keys(), [])

    def testdecode_packetWithBadAttribute(self):
        try:
            self.packet.decode_packet(
                    six.b('\x01\x02\x00\x161234567890123456\x00\x01'))
        except packet.PacketError as e:
            self.failUnless('too small' in str(e))
        else:
            self.fail()

    def testdecode_packetWithEmptyAttribute(self):
        self.packet.decode_packet(
                six.b('\x01\x02\x00\x161234567890123456\x00\x02'))
        self.assertEqual(self.packet[0], [six.b('')])

    def testdecode_packetWithAttribute(self):
        self.packet.decode_packet(
            six.b('\x01\x02\x00\x1b1234567890123456\x00\x07value'))
        self.assertEqual(self.packet[0], [six.b('value')])

    def testdecode_packetWithMultiValuedAttribute(self):
        self.packet.decode_packet(
            six.b('\x01\x02\x00\x1e1234567890123456\x00\x05one\x00\x05two'))
        self.assertEqual(self.packet[0], [six.b('one'), six.b('two')])

    def testdecode_packetWithTwoAttributes(self):
        self.packet.decode_packet(
            six.b('\x01\x02\x00\x1e1234567890123456\x00\x05one\x01\x05two'))
        self.assertEqual(self.packet[0], [six.b('one')])
        self.assertEqual(self.packet[1], [six.b('two')])

    def testdecode_packetWithVendorAttribute(self):
        self.packet.decode_packet(
                six.b('\x01\x02\x00\x1b1234567890123456\x1a\x07value'))
        self.assertEqual(self.packet[26], [six.b('value')])

    def testEncodeKeyValues(self):
        self.assertEqual(self.packet._encode_key_values(1, '1234'), (1, '1234'))

    def testEncodeKey(self):
        self.assertEqual(self.packet._encode_key(1), 1)

    def testadd_attribute(self):
        self.packet.add_attribute(1, 1)
        self.assertEqual(dict.__getitem__(self.packet, 1), [1])
        self.packet.add_attribute(1, 1)
        self.assertEqual(dict.__getitem__(self.packet, 1), [1, 1])
        self.packet.add_attribute(1, [2, 3])
        self.assertEqual(dict.__getitem__(self.packet, 1), [1, 1, 2, 3])


class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.ACCESSREQUEST)


class AuthPacketTests(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testcreate_reply(self):
        reply = self.packet.create_reply(Test_Integer=10)
        self.assertEqual(reply.code, packet.ACCESSACCEPT)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testrequest_packet(self):
        self.assertEqual(self.packet.request_packet(),
                six.b('\x01\x00\x00\x1401234567890ABCDE'))

    def testrequest_packetCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.request_packet()
        self.failUnless(self.packet.authenticator is not None)

    def testrequest_packetCreatesID(self):
        self.packet.id = None
        self.packet.request_packet()
        self.failUnless(self.packet.id is not None)

    def testPwCryptEmptyPassword(self):
        self.assertEqual(self.packet.PwCrypt(''), six.b(''))

    def testPwCryptPassword(self):
        self.assertEqual(self.packet.PwCrypt('Simplon'),
                six.b('\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01'))

    def testPwCryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.PwCrypt(six.u(''))
        self.failUnless(self.packet.authenticator is not None)

    def testpw_decryptEmptyPassword(self):
        self.assertEqual(self.packet.pw_decrypt(six.b('')), six.u(''))

    def testpw_decryptPassword(self):
        self.assertEqual(self.packet.pw_decrypt(
                six.b('\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01')),
                six.u('Simplon'))


class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.ACCOUNTINGREQUEST)

    def testConstructorRawPacket(self):
        raw = six.b('\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
                    '\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7')
        pkt = self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AcctPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testcreate_reply(self):
        reply = self.packet.create_reply(Test_Integer=10)
        self.assertEqual(reply.code, packet.ACCOUNTINGRESPONSE)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testverify_acct_request(self):
        rawpacket = self.packet.request_packet()
        pkt = packet.AcctPacket(secret=six.b('secret'), packet=rawpacket)
        self.assertEqual(pkt.verify_acct_request(), True)

        pkt.secret = six.b('different')
        self.assertEqual(pkt.verify_acct_request(), False)
        pkt.secret = six.b('secret')

        pkt.raw_packet = six.b('X') + pkt.raw_packet[1:]
        self.assertEqual(pkt.verify_acct_request(), False)

    def testrequest_packet(self):
        self.assertEqual(self.packet.request_packet(),
            six.b('\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f'))

    def testrequest_packetSetsId(self):
        self.packet.id = None
        self.packet.request_packet()
        self.failUnless(self.packet.id is not None)
