import socket
import unittest
from pyrad.client import Client
from pyrad.packet import AuthPacket
from pyrad.packet import AcctPacket

BIND_IP = "127.0.0.1"
BIND_PORT = 53535

class MockSocket:
    def __init__(self, domain, type):
        self.domain=domain
        self.type=type
        self.closed=False
        self.options=[]
        self.address=None

    def bind(self, address):
        self.address=address

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
