import fcntl
import os
import socket
import unittest
from pyrad.client import Client
from pyrad.client import Timeout
from pyrad.packet import AuthPacket
from pyrad.packet import AcctPacket
from pyrad.packet import AccessRequest
from pyrad.packet import AccountingRequest
from pyrad.packet import PacketError

BIND_IP = "127.0.0.1"
BIND_PORT = 53535


class MockPacket:
    reply = object()

    def __init__(self, code, verify=False, error=False):
        self.code=code
        self.data={}
        self.verify=verify
        self.error=error

    def CreateReply(self, packet=None):
        if self.error:
            raise PacketError
        return self.reply

    def VerifyReply(self, reply, rawreply):
        return self.verify

    def RequestPacket(self):
        return "request packet"

    def has_key(self, key):
        return self.data.has_key(key)

    def __setitem__(self, key, value):
        self.data[key]=[value]

    def __getitem__(self, key):
        return self.data[key]


class MockSocket:
    def __init__(self, domain, type, data=None):
        self.domain=domain
        self.type=type
        self.closed=False
        self.options=[]
        self.address=None
        self.output=[]

        if data is not None:
            (self.read_end, self.write_end)=os.pipe()
            fcntl.fcntl(self.write_end, fcntl.F_SETFL, os.O_NONBLOCK)
            os.write(self.write_end, data)
            self.data=data
        else:
            self.read_end=1
            self.write_end=None

    def fileno(self):
        return self.read_end

    def bind(self, address):
        self.address=address

    def recv(self, buffer):
        return self.data[:buffer]

    def sendto(self, data, target):
        self.output.append((data, target))

    def setsockopt(self, level, opt, value):
        self.options.append((level, opt, value))

    def close(self):
        self.closed=True


class ConstructionTests(unittest.TestCase):
    def setUp(self):
        self.server=object()

    def testSimpleConstruction(self):
        client=Client(self.server)
        self.failUnless(client.server is self.server)
        self.assertEqual(client.authport, 1812)
        self.assertEqual(client.acctport, 1813)
        self.assertEqual(client.secret, "")
        self.assertEqual(client.retries, 3)
        self.assertEqual(client.timeout, 5)
        self.failUnless(client.dict is None)


    def testParameterOrder(self):
        marker=object()
        client=Client(self.server, 123, 456, "secret", marker)
        self.failUnless(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.secret, "secret")
        self.failUnless(client.dict is marker)


    def testNamedParameters(self):
        marker=object()
        client=Client(server=self.server, authport=123, acctport=456, 
                secret="secret", dict=marker)
        self.failUnless(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.secret, "secret")
        self.failUnless(client.dict is marker)


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.server=object()
        self.client=Client(self.server)
        self.orgsocket=socket.socket
        socket.socket=MockSocket


    def tearDown(self):
        socket.socket=self.orgsocket


    def testReopen(self):
        self.client._SocketOpen()
        sock=self.client._socket
        self.client._SocketOpen()
        self.failUnless(sock is self.client._socket)


    def testBind(self):
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.address, (BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.options,
                [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)])


    def testBindClosesSocket(self):
        self.client._socket=sock=MockSocket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(sock.closed, True)


    def testSendPacket(self):
        def MockSend(self, pkt, port):
            self._mock_pkt=pkt
            self._mock_port=port

        _SendPacket=Client._SendPacket
        Client._SendPacket=MockSend

        self.client.SendPacket(AuthPacket())
        self.assertEqual(self.client._mock_port, self.client.authport)

        self.client.SendPacket(AcctPacket())
        self.assertEqual(self.client._mock_port, self.client.acctport)

        Client._SendPacket= _SendPacket


    def testNoRetries(self):
        self.client.retries=0
        self.assertRaises(Timeout, self.client._SendPacket, None, None)


    def testSingleRetry(self):
        self.client.retries=1
        self.client.timeout=0
        packet=MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(self.client._socket.output,
                [("request packet", (self.server, 432))])


    def testDoubleRetry(self):
        self.client.retries=2
        self.client.timeout=0
        packet=MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(self.client._socket.output,
                [("request packet", (self.server, 432)),
                 ("request packet", (self.server, 432))])


    def testAuthDelay(self):
        self.client.retries=2
        self.client.timeout=1
        packet=MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.failIf(packet.has_key("Acct-Delay-Time"))


    def testSingleAccountDelay(self):
        self.client.retries=2
        self.client.timeout=1
        packet=MockPacket(AccountingRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [1])


    def testDoubleAccountDelay(self):
        self.client.retries=3
        self.client.timeout=1
        packet=MockPacket(AccountingRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [2])


    def testIgnorePacketError(self):
        self.client.retries=1
        self.client.timeout=1
        self.client._socket=MockSocket(1, 2, "valid reply")
        packet=MockPacket(AccountingRequest, verify=True, error=True)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)


    def testValidReply(self):
        self.client.retries=1
        self.client.timeout=1
        self.client._socket=MockSocket(1, 2, "valid reply")
        packet=MockPacket(AccountingRequest, verify=True)
        reply=self.client._SendPacket(packet, 432)
        self.failUnless(reply is packet.reply)


    def testInvalidReply(self):
        self.client.retries=1
        self.client.timeout=1
        self.client._socket=MockSocket(1, 2, "invalid reply")
        packet=MockPacket(AccountingRequest, verify=False)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)



class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server=object()
        self.client=Client(self.server, secret="zeer geheim")


    def testCreateAuthPacket(self):
        packet=self.client.CreateAuthPacket(id=15)
        self.failUnless(isinstance(packet, AuthPacket))
        self.failUnless(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, "zeer geheim")


    def testCreateAcctPacket(self):
        packet=self.client.CreateAcctPacket(id=15)
        self.failUnless(isinstance(packet, AcctPacket))
        self.failUnless(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, "zeer geheim")

