import select
import socket
import unittest
from .mock import MockFd
from .mock import MockPoll
from .mock import MockSocket
from .mock import MockClassMethod
from .mock import UnmockClassMethods
from pyrad.proxy import Proxy
from pyrad import packet
from pyrad.packet import AccessAccept
from pyrad.packet import AccessRequest
from pyrad.server import ServerPacketError
from pyrad.server import Server


class TrivialObject:
    """dummy object"""


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket = socket.socket
        socket.socket = MockSocket
        self.proxy = Proxy()
        self.proxy._fdmap = {}

    def tearDown(self):
        socket.socket = self.orgsocket

    def testProxyFd(self):
        self.proxy._poll = MockPoll()
        self.proxy._PrepareSockets()
        self.assertTrue(isinstance(self.proxy._proxyfd, MockSocket))
        self.assertEqual(list(self.proxy._fdmap.keys()), [1])
        self.assertEqual(self.proxy._poll.registry,
                         {1: select.POLLIN | select.POLLPRI | select.POLLERR})


class ProxyPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.proxy = Proxy()
        self.proxy.hosts['host'] = TrivialObject()
        self.proxy.hosts['host'].secret = 'supersecret'
        self.packet = TrivialObject()
        self.packet.code = AccessAccept
        self.packet.source = ('host', 'port')

    def testHandleProxyPacketUnknownHost(self):
        self.packet.source = ('stranger', 'port')
        try:
            self.proxy._HandleProxyPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('unknown host' in str(e))
        else:
            self.fail()

    def testHandleProxyPacketSetsSecret(self):
        self.proxy._HandleProxyPacket(self.packet)
        self.assertEqual(self.packet.secret, 'supersecret')

    def testHandleProxyPacketMappedAddress(self):
        self.proxy.hosts['127.0.0.1'] = TrivialObject()
        self.proxy.hosts['127.0.0.1'].secret = 'v4secret'
        self.packet.source = ('::ffff:127.0.0.1', 1812, 0, 0)
        self.proxy._HandleProxyPacket(self.packet)
        self.assertEqual(self.packet.secret, 'v4secret')
        self.assertEqual(self.packet.source, ('::ffff:127.0.0.1', 1812, 0, 0))

    def testHandleProxyPacketHandlesWrongPacket(self):
        self.packet.code = AccessRequest
        try:
            self.proxy._HandleProxyPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('non-response' in str(e))
        else:
            self.fail()

    def testHandleProxyPacketRejectsRequests(self):
        for code in (packet.AccessRequest, packet.AccountingRequest,
                     packet.StatusServer, packet.StatusClient,
                     packet.CoARequest, packet.DisconnectRequest):
            with self.subTest(code=code):
                self.packet.code = code
                self.assertRaises(ServerPacketError,
                                  self.proxy._HandleProxyPacket, self.packet)

    def testHandleProxyPacketAcceptsAllReplies(self):
        # Access-Challenge (RFC 2865 section 4.4) and the CoA and Disconnect
        # replies (RFC 5176) are forwarded like the other replies
        for code in (packet.AccessAccept, packet.AccessReject,
                     packet.AccountingResponse, packet.AccessChallenge,
                     packet.CoAACK, packet.CoANAK,
                     packet.DisconnectACK, packet.DisconnectNAK):
            with self.subTest(code=code):
                self.packet.code = code
                self.proxy._HandleProxyPacket(self.packet)


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.proxy = Proxy()
        self.proxy._proxyfd = MockFd()

    def tearDown(self):
        UnmockClassMethods(Proxy)
        UnmockClassMethods(Server)

    def testProcessInputNonProxyPort(self):
        fd = MockFd(fd=111)
        MockClassMethod(Server, '_ProcessInput')
        self.proxy._ProcessInput(fd)
        self.assertEqual(self.proxy.called,
                         [('_ProcessInput', (fd,), {})])

    def testProcessInput(self):
        MockClassMethod(Proxy, '_GrabPacket')
        MockClassMethod(Proxy, '_HandleProxyPacket')
        self.proxy._ProcessInput(self.proxy._proxyfd)
        self.assertEqual([x[0] for x in self.proxy.called],
                         ['_GrabPacket', '_HandleProxyPacket'])


if not hasattr(select, 'poll'):
    del SocketTests
