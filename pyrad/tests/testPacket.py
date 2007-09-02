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

    def setUp(self):
        self.path=os.path.join(home, "tests", "data")
        self.dict=Dictionary(os.path.join(self.path, "simple"))


    def testBasicConstructor(self):
        pkt=packet.Packet()
        self.failUnless(isinstance(pkt.code, int))
        self.failUnless(isinstance(pkt.id, int))
        self.failUnless(isinstance(pkt.secret, str))


    def testNamedConstructor(self):
        pkt=packet.Packet(code=26, id=38, secret="secret",
                authenticator="authenticator",
                dict="fakedict")
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, "secret")
        self.assertEqual(pkt.authenticator, "authenticator")
        self.assertEqual(pkt.dict, "fakedict")


    def testConstructWithDictionary(self):
        pkt=packet.Packet(dict=self.dict)
        self.failUnless(pkt.dict is self.dict)


    def testConstructorIgnoredParameters(self):
        marker=[]
        pkt=packet.Packet(fd=marker)
        self.failIf(getattr(pkt, "fd", None) is marker)


    def testConstructorWithAttributes(self):
        pkt=packet.Packet(dict=self.dict, Test_String="this works")
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
        self.assertEqual("Test-String" in self.packet, True)


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

