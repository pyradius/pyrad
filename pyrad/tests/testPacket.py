import os
import unittest
from pyrad import packet
from pyrad.tests import home
from pyrad.dictionary import Dictionary

class UtilityTests(unittest.TestCase):

    def testGenerateID(self):
        id=packet.CreateID()
        self.failUnless(isinstance(id, int))
        newid=packet.CreateID()
        self.assertNotEqual(id, newid)



class PacketConstructionTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.path=os.path.join(home, "tests", "data")
        self.dict=Dictionary(os.path.join(self.path, "simple"))


    def testBasicConstructor(self):
        pkt=self.klass()
        self.failUnless(isinstance(pkt.code, int))
        self.failUnless(isinstance(pkt.id, int))
        self.failUnless(isinstance(pkt.secret, str))


    def testNamedConstructor(self):
        pkt=self.klass(code=26, id=38, secret="secret",
                authenticator="authenticator",
                dict="fakedict")
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, "secret")
        self.assertEqual(pkt.authenticator, "authenticator")
        self.assertEqual(pkt.dict, "fakedict")


    def testConstructWithDictionary(self):
        pkt=self.klass(dict=self.dict)
        self.failUnless(pkt.dict is self.dict)


    def testConstructorIgnoredParameters(self):
        marker=[]
        pkt=self.klass(fd=marker)
        self.failIf(getattr(pkt, "fd", None) is marker)


    def testConstructorWithAttributes(self):
        pkt=self.klass(dict=self.dict, Test_String="this works")
        self.assertEqual(pkt["Test-String"], ["this works"])



class PacketTests(unittest.TestCase):

    def setUp(self):
        self.path=os.path.join(home, "tests", "data")
        self.dict=Dictionary(os.path.join(self.path, "full"))
        self.packet=packet.Packet(id=0, secret="secret",
                authenticator="01234567890ABCDEF", dict=self.dict)


    def testCreateReply(self):
        reply=self.packet.CreateReply(Test_Integer=10)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply["Test-Integer"], [10])


    def testAttributeAccess(self):
        self.packet["Test-Integer"]=10
        self.assertEqual(self.packet["Test-Integer"], [10])
        self.assertEqual(self.packet[3], ["\x00\x00\x00\x0a"])

        self.packet["Test-String"]="dummy"
        self.assertEqual(self.packet["Test-String"], ["dummy"])
        self.assertEqual(self.packet[1], ["dummy"])


    def testAttributeValueAccess(self):
        self.packet["Test-Integer"]="Three"
        self.assertEqual(self.packet["Test-Integer"], ["Three"])
        self.assertEqual(self.packet[3], ["\x00\x00\x00\x03"])


    def testVendorAttributeAccess(self):
        self.packet["Simplon-Number"]=10
        self.assertEqual(self.packet["Simplon-Number"], [10])
        self.assertEqual(self.packet[(16,1)], ["\x00\x00\x00\x0a"])

        self.packet["Simplon-Number"]="Four"
        self.assertEqual(self.packet["Simplon-Number"], ["Four"])
        self.assertEqual(self.packet[(16,1)], ["\x00\x00\x00\x04"])


    def testRawAttributeAccess(self):
        marker=[""]
        self.packet[1]=marker
        self.failUnless(self.packet[1] is marker)
        self.assertEqual(self.packet["Test-String"], marker)

        self.packet[(16,1)]=marker
        self.failUnless(self.packet[(16,1)] is marker)


    def testHasKey(self):
        self.assertEqual(self.packet.has_key("Test-String"), False)
        self.assertEqual("Test-String" in self.packet, False)
        self.packet["Test-String"]="dummy"
        self.assertEqual(self.packet.has_key("Test-String"), True)
        self.assertEqual(self.packet.has_key(1), True)
        self.assertEqual(1 in self.packet, True)


    def testHasKeyWithUnknownKey(self):
        self.assertEqual(self.packet.has_key("Unknown-Attribute"), False)
        self.assertEqual("Unknown-Attribute" in self.packet, False)


    def testDelItem(self):
        self.packet["Test-String"]="dummy"
        del self.packet["Test-String"]
        self.assertEqual(self.packet.has_key("Test-String"), False)
        self.packet["Test-String"]="dummy"
        del self.packet[1]
        self.assertEqual(self.packet.has_key("Test-String"), False)


    def testKeys(self):
        self.assertEqual(self.packet.keys(), [])
        self.packet["Test-String"]="dummy"
        self.assertEqual(self.packet.keys(), ["Test-String"])
        self.packet["Test-Integer"]=10
        self.assertEqual(self.packet.keys(), ["Test-String", "Test-Integer"])
        self.packet.data[12345]=None
        self.assertEqual(self.packet.keys(),
                        ["Test-String", "Test-Integer", 12345])


    def testCreateAuthenticator(self):
        a=packet.Packet.CreateAuthenticator()
        self.failUnless(isinstance(a, str))
        self.assertEqual(len(a), 16)

        b=packet.Packet.CreateAuthenticator()
        self.assertNotEqual(a, b)


    def testGenerateID(self):
        id=self.packet.CreateID()
        self.failUnless(isinstance(id, int))
        newid=self.packet.CreateID()
        self.assertNotEqual(id, newid)


    def testReplyPacket(self):
        reply=self.packet.ReplyPacket()
        self.assertEqual(reply, "\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c"
                                "\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7")

    def testVerifyReply(self):
        reply=self.packet.CreateReply()
        self.assertEqual(self.packet.VerifyReply(reply), True)

        reply.id+=1
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.id=self.packet.id

        reply.secret="different"
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.secret=self.packet.secret

        reply.authenticator="X"*16
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.authenticator=self.packet.authenticator


    def testPktEncodeAttribute(self):
        encode=self.packet._PktEncodeAttribute

        # Encode a normal attribute
        self.assertEqual(encode(1, "value"), "\x01\x07value")
        # Encode a vendor attribute
        self.assertEqual(encode((1,2), "value"),
                "\x1a\x0d\x00\x00\x00\x01\x02\x07value")


    def testPktEncodeAttributes(self):
        self.packet[1]=["value"]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                "\x01\x07value")

        self.packet.clear()
        self.packet[(1,2)]=["value"]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                "\x1a\x0d\x00\x00\x00\x01\x02\x07value")

        self.packet.clear()
        self.packet[1]=["one", "two", "three"]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                "\x01\x05one\x01\x05two\x01\x07three")

        self.packet.clear()
        self.packet[1]=["value"]
        self.packet[(1,2)]=["value"]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                "\x1a\x0d\x00\x00\x00\x01\x02\x07value\x01\x07value")


    def testPktDecodeVendorAttribute(self):
        decode=self.packet._PktDecodeVendorAttribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(""), (26, ""))
        self.assertEqual(decode("12345"), (26, "12345"))

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(decode("\x00\x00\x00\x01\x02\x06value"),
                (26, "\x00\x00\x00\x01\x02\x06value"))

        # Proper RFC2865 recommended form
        self.assertEqual(decode("\x00\x00\x00\x01\x02\x07value"),
                ((1L,2), "value"))


    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.DecodePacket("")
        except packet.PacketError, e:
            self.failUnless("header is corrupt" in str(e))
        else:
            self.fail()


    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.DecodePacket("\x00\x00\x00\x001234567890123456")
        except packet.PacketError, e:
            self.failUnless("invalid length" in str(e))
        else:
            self.fail()


    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.DecodePacket("\x00\x00\x24\x00" +  (0x2400-4)*"X")
        except packet.PacketError, e:
            self.failUnless("too long" in str(e))
        else:
            self.fail()


    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.DecodePacket("\x01\x02\x00\x151234567890123456\x00")
        except packet.PacketError, e:
            self.failUnless("header is corrupt" in str(e))
        else:
            self.fail()


    def testDecodePacketWithoutAttributes(self):
        self.packet.DecodePacket("\x01\x02\x00\x141234567890123456")
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, "1234567890123456")
        self.assertEqual(self.packet.keys(), [])


    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.DecodePacket("\x01\x02\x00\x161234567890123456\x00\x01")
        except packet.PacketError, e:
            self.failUnless("too small" in str(e))
        else:
            self.fail()


    def testDecodePacketWithEmptyAttribute(self):
        self.packet.DecodePacket("\x01\x02\x00\x161234567890123456\x00\x02")
        self.assertEqual(self.packet[0], [""])


    def testDecodePacketWithAttribute(self):
        self.packet.DecodePacket("\x01\x02\x00\x1b1234567890123456\x00\x07value")
        self.assertEqual(self.packet[0], ["value"])


    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.DecodePacket("\x01\x02\x00\x1e1234567890123456\x00\x05one\x00\x05two")
        self.assertEqual(self.packet[0], ["one", "two"])


    def testDecodePacketWithTwoAttributes(self):
        self.packet.DecodePacket("\x01\x02\x00\x1e1234567890123456\x00\x05one\x01\x05two")
        self.assertEqual(self.packet[0], ["one"])
        self.assertEqual(self.packet[1], ["two"])


    def testDecodePacketWithVendorAttribute(self):
        self.packet.DecodePacket("\x01\x02\x00\x1b1234567890123456\x1a\x07value")
        self.assertEqual(self.packet[26], ["value"])


    def testEncodeKeyValues(self):
        self.assertEqual(self.packet._EncodeKeyValues(1, "1234"), (1, "1234"))


    def testEncodeKey(self):
        self.assertEqual(self.packet._EncodeKey(1), 1)


    def testAddAttribute(self):
        self.packet.AddAttribute(1, 1)
        self.assertEqual(self.packet.data[1], [1])
        self.packet.AddAttribute(1, 1)
        self.assertEqual(self.packet.data[1], [1, 1])



class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt=self.klass()
        self.assertEqual(pkt.code, packet.AccessRequest)



class AuthPacketTests(unittest.TestCase):

    def setUp(self):
        self.path=os.path.join(home, "tests", "data")
        self.dict=Dictionary(os.path.join(self.path, "full"))
        self.packet=packet.AuthPacket(id=0, secret="secret",
                authenticator="01234567890ABCDEF", dict=self.dict)


    def testCreateReply(self):
        reply=self.packet.CreateReply(Test_Integer=10)
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply["Test-Integer"], [10])


    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
                "\x01\x00\x00\x1401234567890ABCDE")

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator=None
        self.packet.RequestPacket()
        self.failUnless(self.packet.authenticator is not None)


    def testRequestPacketCreatesID(self):
        self.packet.id=None
        self.packet.RequestPacket()
        self.failUnless(self.packet.id is not None)


    def testPwCryptEmptyPassword(self):
        self.assertEqual(self.packet.PwCrypt(""), "")


    def testPwCryptPassword(self):
        self.assertEqual(self.packet.PwCrypt("Simplon"),
                         "\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01")


    def testPwCryptSetsAuthenticator(self):
        self.packet.authenticator=None
        self.packet.PwCrypt("")
        self.failUnless(self.packet.authenticator is not None)


    def testPwDecryptEmptyPassword(self):
        self.assertEqual(self.packet.PwDecrypt(""), "")


    def testPwDecryptPassword(self):
        self.assertEqual(self.packet.PwDecrypt(
                "\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01"),
                         "Simplon")



class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt=self.klass()
        self.assertEqual(pkt.code, packet.AccountingRequest)


    def testConstructorRawPacket(self):
        raw="\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c" \
            "\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7"
        pkt=self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):

    def setUp(self):
        self.path=os.path.join(home, "tests", "data")
        self.dict=Dictionary(os.path.join(self.path, "full"))
        self.packet=packet.AcctPacket(id=0, secret="secret",
                authenticator="01234567890ABCDEF", dict=self.dict)


    def testCreateReply(self):
        reply=self.packet.CreateReply(Test_Integer=10)
        self.assertEqual(reply.code, packet.AccountingResponse)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply["Test-Integer"], [10])


    def testVerifyAcctRequest(self):
        rawpacket=self.packet.RequestPacket()
        pkt=packet.AcctPacket(secret="secret", packet=rawpacket)
        self.assertEqual(pkt.VerifyAcctRequest(), True)

        pkt.secret="different"
        self.assertEqual(pkt.VerifyAcctRequest(), False)
        pkt.secret="secret"

        pkt.raw_packet="X" + pkt.raw_packet[1:]
        self.assertEqual(pkt.VerifyAcctRequest(), False)


    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
            "\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f")


    def testRequestPacketSetsId(self):
        self.packet.id=None
        self.packet.RequestPacket()
        self.failUnless(self.packet.id is not None)

