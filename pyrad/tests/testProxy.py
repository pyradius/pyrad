import select
import socket
import unittest
from pyrad.proxy import Proxy
from pyrad.packet import ACCESSACCEPT
from pyrad.packet import ACCESSREQUEST
from pyrad.server import ServerPacketError
from pyrad.server import Server
from pyrad.tests.mock import MockFd
from pyrad.tests.mock import MockPoll
from pyrad.tests.mock import MockSocket
from pyrad.tests.mock import MockClassMethod
from pyrad.tests.mock import UnmockClassMethods


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
        self.proxy._prepare_sockets()
        self.failUnless(isinstance(self.proxy._proxyfd, MockSocket))
        self.assertEqual(list(self.proxy._fdmap.keys()), [1])
        self.assertEqual(self.proxy._poll.registry,
                         [(1, select.POLLIN | select.POLLPRI | select.POLLERR)])


class ProxyPacketHandlingTests(unittest.TestCase):

    def setUp(self):
        self.proxy = Proxy()
        self.proxy.hosts['host'] = TrivialObject()
        self.proxy.hosts['host'].secret = 'supersecret'
        self.packet = TrivialObject()
        self.packet.code = ACCESSACCEPT
        self.packet.source = ('host', 'port')

    def testHandleProxyPacketUnknownHost(self):
        self.packet.source = ('stranger', 'port')
        try:
            self.proxy._handle_proxy_packet(self.packet)
        except ServerPacketError as e:
            self.failUnless('unknown host' in str(e))
        else:
            self.fail()

    def testHandleProxyPacketSetsSecret(self):
        self.proxy._handle_proxy_packet(self.packet)
        self.assertEqual(self.packet.secret, 'supersecret')

    def testHandleProxyPacketHandlesWrongPacket(self):
        self.packet.code = ACCESSREQUEST
        try:
            self.proxy._handle_proxy_packet(self.packet)
        except ServerPacketError as e:
            self.failUnless('non-response' in str(e))
        else:
            self.fail()


class OtherTests(unittest.TestCase):

    def setUp(self):
        self.proxy = Proxy()
        self.proxy._proxyfd = MockFd()

    def tearDown(self):
        UnmockClassMethods(Proxy)
        UnmockClassMethods(Server)

    def testProcessInputNonProxyPort(self):
        fd = MockFd(fd=111)
        MockClassMethod(Server, '_process_input')
        self.proxy._process_input(fd)
        self.assertEqual(self.proxy.called,
                         [('_process_input', (fd,), {})])

    def testProcessInput(self):
        MockClassMethod(Proxy, '_grab_packet')
        MockClassMethod(Proxy, '_handle_proxy_packet')
        self.proxy._process_input(self.proxy._proxyfd)
        self.assertEqual([x[0] for x in self.proxy.called],
                         ['_grab_packet', '_handle_proxy_packet'])


if not hasattr(select, 'poll'):
    del SocketTests
