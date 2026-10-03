import select
import socket
import unittest
from .mock import MockFinished
from .mock import MockFd
from .mock import MockPoll
from .mock import MockSocket
from .mock import MockClassMethod
from .mock import UnmockClassMethods
from pyrad.packet import PacketError
from pyrad.server import RemoteHost
from pyrad.server import Server
from pyrad.server import ServerPacketError
from pyrad.packet import AccessRequest
from pyrad.packet import AccountingRequest
from pyrad.packet import AccountingResponse
from pyrad.packet import AcctPacket
from pyrad.packet import CoAPacket
from pyrad.packet import CoARequest
from pyrad.packet import DisconnectRequest


class TrivialObject:
    """dummy object"""


class RemoteHostTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host = RemoteHost('address', 'secret', 'name', 'authport', 'acctport', 'coaport')
        self.assertEqual(host.address, 'address')
        self.assertEqual(host.secret, 'secret')
        self.assertEqual(host.name, 'name')
        self.assertEqual(host.authport, 'authport')
        self.assertEqual(host.acctport, 'acctport')
        self.assertEqual(host.coaport, 'coaport')

    def testNamedConstruction(self):
        host = RemoteHost(address='address', secret='secret', name='name',
                          authport='authport', acctport='acctport', coaport='coaport')
        self.assertEqual(host.address, 'address')
        self.assertEqual(host.secret, 'secret')
        self.assertEqual(host.name, 'name')
        self.assertEqual(host.authport, 'authport')
        self.assertEqual(host.acctport, 'acctport')
        self.assertEqual(host.coaport, 'coaport')


class ServerConstructiontests(unittest.TestCase):
    def testSimpleConstruction(self):
        server = Server()
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, 1812)
        self.assertEqual(server.acctport, 1813)
        self.assertEqual(server.coaport, 3799)
        self.assertEqual(server.hosts, {})

    def testParameterOrder(self):
        server = Server([], 'authport', 'acctport', 'coaport', 'hosts', 'dict')
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, 'authport')
        self.assertEqual(server.acctport, 'acctport')
        self.assertEqual(server.coaport, 'coaport')
        self.assertEqual(server.dict, 'dict')

    def testBindDuringConstruction(self):
        def BindToAddress(self, addr):
            self.bound.append(addr)
        bta = Server.BindToAddress
        Server.BindToAddress = BindToAddress

        Server.bound = []
        server = Server(['one', 'two', 'three'])
        self.assertEqual(server.bound, ['one', 'two', 'three'])
        del Server.bound

        Server.BindToAddress = bta


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket = socket.socket
        socket.socket = MockSocket
        self.server = Server()

    def tearDown(self):
        socket.socket = self.orgsocket

    def testBind(self):
        self.server.BindToAddress('192.168.13.13')
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address,
                         ('192.168.13.13', 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address,
                         ('192.168.13.13', 1813))

    def testBindv6(self):
        self.server.BindToAddress('2001:db8:123::1')
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address,
                         ('2001:db8:123::1', 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address,
                         ('2001:db8:123::1', 1813))

    def testBindCoA(self):
        self.server.coa_enabled = True
        self.server.BindToAddress('192.168.13.13')
        self.assertEqual(self.server.coafds[0].address, ('192.168.13.13', 3799))

    def testBindUnknownAddress(self):
        def getaddrinfo(*args):
            raise socket.gaierror
        orggetaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = getaddrinfo
        try:
            self.server.BindToAddress('unknown.invalid')
        finally:
            socket.getaddrinfo = orggetaddrinfo
        self.assertEqual(self.server.authfds, [])

    def testPrepareSocketCoAFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.coa_enabled = True
        self.server.coafds = [MockFd(12)]
        self.server._PrepareSockets()
        self.assertEqual(self.server._realcoafds, [12])

    def testGrabPacket(self):
        def gen(data):
            res = TrivialObject()
            res.data = data
            return res

        fd = MockFd()
        fd.source = object()
        pkt = self.server._GrabPacket(gen, fd)
        self.assertTrue(isinstance(pkt, TrivialObject))
        self.assertTrue(pkt.fd is fd)
        self.assertTrue(pkt.source is fd.source)
        self.assertTrue(pkt.data is fd.data)

    def testGrabPacketDecodeError(self):
        def gen(data):
            raise AttributeError('boom')

        with self.assertRaises(PacketError) as cm:
            self.server._GrabPacket(gen, MockFd())
        self.assertIn('AttributeError: boom', str(cm.exception))

    def testPrepareSocketNoFds(self):
        self.server._poll = MockPoll()
        self.server._PrepareSockets()

        self.assertEqual(self.server._poll.registry, {})
        self.assertEqual(self.server._realauthfds, [])
        self.assertEqual(self.server._realacctfds, [])

    def testPrepareSocketAuthFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.authfds = [MockFd(12), MockFd(14)]
        self.server._PrepareSockets()

        self.assertEqual(list(self.server._fdmap.keys()), [12, 14])
        self.assertEqual(self.server._poll.registry,
                         {12: select.POLLIN | select.POLLPRI | select.POLLERR,
                          14: select.POLLIN | select.POLLPRI | select.POLLERR})

    def testPrepareSocketAcctFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.acctfds = [MockFd(12), MockFd(14)]
        self.server._PrepareSockets()

        self.assertEqual(list(self.server._fdmap.keys()), [12, 14])
        self.assertEqual(self.server._poll.registry,
                         {12: select.POLLIN | select.POLLPRI | select.POLLERR,
                          14: select.POLLIN | select.POLLPRI | select.POLLERR})


class AuthPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        # these tests cover the dispatch, not the Message-Authenticator,
        # which the dummy packets below cannot carry
        self.server = Server(enforce_ma=False)
        self.server.hosts['host'] = TrivialObject()
        self.server.hosts['host'].secret = 'supersecret'
        self.packet = TrivialObject()
        self.packet.code = AccessRequest
        self.packet.source = ('host', 'port')
        self.packet.message_authenticator = None

    def testHandleAuthPacketUnknownHost(self):
        self.packet.source = ('stranger', 'port')
        try:
            self.server._HandleAuthPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('unknown host' in str(e))
        else:
            self.fail()

    def testHandleAuthPacketWrongPort(self):
        self.packet.code = AccountingRequest
        try:
            self.server._HandleAuthPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('port' in str(e))
        else:
            self.fail()

    def testHandleAuthPacket(self):
        def HandleAuthPacket(self, pkt):
            self.handled = pkt
        hap = Server.HandleAuthPacket
        Server.HandleAuthPacket = HandleAuthPacket

        self.server._HandleAuthPacket(self.packet)
        self.assertTrue(self.server.handled is self.packet)

        Server.HandleAuthPacket = hap


class AcctPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server = Server(enable_pkt_verify=False)
        self.server.hosts['host'] = TrivialObject()
        self.server.hosts['host'].secret = 'supersecret'
        self.packet = TrivialObject()
        self.packet.code = AccountingRequest
        self.packet.source = ('host', 'port')
        self.packet.message_authenticator = None

    def testHandleAcctPacketUnknownHost(self):
        self.packet.source = ('stranger', 'port')
        try:
            self.server._HandleAcctPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('unknown host' in str(e))
        else:
            self.fail()

    def testHandleAcctPacketWrongPort(self):
        self.packet.code = AccessRequest
        try:
            self.server._HandleAcctPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('port' in str(e))
        else:
            self.fail()

    def testHandleAcctPacket(self):
        def HandleAcctPacket(self, pkt):
            self.handled = pkt
        hap = Server.HandleAcctPacket
        Server.HandleAcctPacket = HandleAcctPacket

        self.server._HandleAcctPacket(self.packet)
        self.assertTrue(self.server.handled is self.packet)

        Server.HandleAcctPacket = hap


class CoaPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server = Server(enable_pkt_verify=False)
        self.server.hosts['0.0.0.0'] = TrivialObject()
        self.server.hosts['0.0.0.0'].secret = 'supersecret'
        self.packet = TrivialObject()
        self.packet.source = ('host', 'port')
        self.packet.message_authenticator = None
        self.handled = []
        self.server.HandleCoaPacket = lambda pkt: self.handled.append(('coa', pkt))
        self.server.HandleDisconnectPacket = lambda pkt: self.handled.append(('disconnect', pkt))

    def testHandleCoaPacket(self):
        self.packet.code = CoARequest
        self.server._HandleCoaPacket(self.packet)
        self.assertEqual(self.handled, [('coa', self.packet)])
        # the secret of the default host is used for unknown hosts
        self.assertEqual(self.packet.secret, 'supersecret')

    def testHandleDisconnectPacket(self):
        self.packet.code = DisconnectRequest
        self.server._HandleCoaPacket(self.packet)
        self.assertEqual(self.handled, [('disconnect', self.packet)])

    def testHandleCoaPacketWrongPort(self):
        self.packet.code = AccessRequest
        self.assertRaises(ServerPacketError, self.server._HandleCoaPacket, self.packet)
        self.assertEqual(self.handled, [])


class PacketVerificationTests(unittest.TestCase):
    """Accounting, CoA and Disconnect requests must be signed with the
    shared secret (RFC 2866 section 3, RFC 5176 section 3.5)."""

    def setUp(self):
        self.server = Server(hosts={'127.0.0.1': RemoteHost('127.0.0.1', b'secret', 'localhost')})
        self.handled = []
        self.server.HandleAcctPacket = self.handled.append
        self.server.HandleCoaPacket = self.handled.append
        self.server.HandleDisconnectPacket = self.handled.append

    def receive(self, handler, create, req):
        pkt = create(packet=req.RequestPacket())
        pkt.source = ('127.0.0.1', 1813)
        handler(pkt)

    def acct(self, req):
        self.receive(self.server._HandleAcctPacket, self.server.CreateAcctPacket, req)

    def coa(self, req):
        self.receive(self.server._HandleCoaPacket, self.server.CreateCoAPacket, req)

    def testValidRequests(self):
        self.acct(AcctPacket(secret=b'secret'))
        self.coa(CoAPacket(secret=b'secret'))
        self.coa(CoAPacket(code=DisconnectRequest, secret=b'secret'))
        self.assertEqual(len(self.handled), 3)

    def testInvalidAcctRequest(self):
        self.assertRaises(PacketError, self.acct, AcctPacket(secret=b'wrong'))
        self.assertEqual(self.handled, [])

    def testInvalidCoARequest(self):
        self.assertRaises(PacketError, self.coa, CoAPacket(secret=b'wrong'))
        self.assertRaises(PacketError, self.coa,
                          CoAPacket(code=DisconnectRequest, secret=b'wrong'))
        self.assertEqual(self.handled, [])

    def testAccountingResponseOnAcctPort(self):
        reply = AcctPacket(code=AccountingResponse, secret=b'secret',
                           authenticator=16 * b'\x00')
        pkt = self.server.CreateAcctPacket(packet=reply.ReplyPacket())
        pkt.source = ('127.0.0.1', 1813)
        self.assertRaises(ServerPacketError, self.server._HandleAcctPacket, pkt)
        self.assertEqual(self.handled, [])

    def testVerificationDisabled(self):
        self.server.enable_pkt_verify = False
        self.acct(AcctPacket(secret=b'wrong'))
        self.coa(CoAPacket(secret=b'wrong'))
        self.assertEqual(len(self.handled), 2)


class MappedAddressTests(unittest.TestCase):
    """A server bound to '::' (dual stack) sees IPv4 clients with an
    IPv4-mapped IPv6 source address."""

    def setUp(self):
        self.server = Server(enable_pkt_verify=False)
        self.server.hosts['127.0.0.1'] = RemoteHost('127.0.0.1', b'secret', 'v4')
        self.packet = TrivialObject()
        self.packet.code = AccountingRequest
        self.packet.source = ('::ffff:127.0.0.1', 1813, 0, 0)
        self.packet.message_authenticator = None
        self.server.HandleAcctPacket = lambda pkt: None

    def testMappedAddressUsesIPv4Host(self):
        self.server._HandleAcctPacket(self.packet)
        self.assertEqual(self.packet.secret, b'secret')
        # the source is kept as received, it is needed to send the reply
        self.assertEqual(self.packet.source, ('::ffff:127.0.0.1', 1813, 0, 0))

    def testMappedAddressIsNotDefaultHost(self):
        self.server.hosts['0.0.0.0'] = RemoteHost('0.0.0.0', b'default', 'default')
        self.server._HandleAcctPacket(self.packet)
        self.assertEqual(self.packet.secret, b'secret')

    def testExactMatchWins(self):
        self.server.hosts['::ffff:127.0.0.1'] = RemoteHost(
            '::ffff:127.0.0.1', b'mapped', 'mapped')
        self.server._HandleAcctPacket(self.packet)
        self.assertEqual(self.packet.secret, b'mapped')

    def testUnknownMappedAddress(self):
        self.packet.source = ('::ffff:192.0.2.1', 1813, 0, 0)
        self.assertRaises(ServerPacketError, self.server._HandleAcctPacket, self.packet)

    def testIPv6Address(self):
        self.server.hosts['::1'] = RemoteHost('::1', b'v6', 'v6')
        self.packet.source = ('::1', 1813, 0, 0)
        self.server._HandleAcctPacket(self.packet)
        self.assertEqual(self.packet.secret, b'v6')


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()

    def tearDown(self):
        UnmockClassMethods(Server)

    def testCreateReplyPacket(self):
        class TrivialPacket:
            source = object()

            def CreateReply(self, **kw):
                reply = TrivialObject()
                reply.kw = kw
                return reply

        reply = self.server.CreateReplyPacket(TrivialPacket(),
                                              one='one', two='two')
        self.assertTrue(isinstance(reply, TrivialObject))
        self.assertTrue(reply.source is TrivialPacket.source)
        self.assertEqual(reply.kw, dict(one='one', two='two'))

    def testAuthProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = [1]
        MockClassMethod(Server, '_GrabPacket')
        MockClassMethod(Server, '_HandleAuthPacket')

        self.server._ProcessInput(fd)
        self.assertEqual([x[0] for x in self.server.called],
                         ['_GrabPacket', '_HandleAuthPacket'])
        self.assertEqual(self.server.called[0][1][1], fd)

    def testAcctProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = []
        self.server._realacctfds = [1]
        MockClassMethod(Server, '_GrabPacket')
        MockClassMethod(Server, '_HandleAcctPacket')

        self.server._ProcessInput(fd)
        self.assertEqual([x[0] for x in self.server.called],
                         ['_GrabPacket', '_HandleAcctPacket'])
        self.assertEqual(self.server.called[0][1][1], fd)

    def testCoaProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = []
        self.server._realacctfds = []
        self.server.coa_enabled = True
        MockClassMethod(Server, '_GrabPacket')
        MockClassMethod(Server, '_HandleCoaPacket')

        self.server._ProcessInput(fd)
        self.assertEqual([x[0] for x in self.server.called],
                         ['_GrabPacket', '_HandleCoaPacket'])

    def testUnknownProcessInput(self):
        self.server._realauthfds = []
        self.server._realacctfds = []
        self.assertRaises(ServerPacketError, self.server._ProcessInput, MockFd(1))


class ServerRunTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.origpoll = select.poll
        select.poll = MockPoll

    def tearDown(self):
        MockPoll.results = []
        select.poll = self.origpoll
        UnmockClassMethods(Server)

    def testRunInitializes(self):
        MockClassMethod(Server, '_PrepareSockets')
        self.assertRaises(MockFinished, self.server.Run)
        self.assertEqual(self.server.called, [('_PrepareSockets', (), {})])
        self.assertTrue(isinstance(self.server._fdmap, dict))
        self.assertTrue(isinstance(self.server._poll, MockPoll))

    def testRunIgnoresPollErrors(self):
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLERR)]
        self.assertRaises(MockFinished, self.server.Run)

    def testRunIgnoresServerPacketErrors(self):
        def RaisePacketError(self, fd):
            raise ServerPacketError
        MockClassMethod(Server, '_ProcessInput', RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.Run)

    def testRunIgnoresPacketErrors(self):
        def RaisePacketError(self, fd):
            raise PacketError
        MockClassMethod(Server, '_ProcessInput', RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.Run)

    def testRunIgnoresHandlerErrors(self):
        def RaiseError(self, fd):
            raise ValueError
        MockClassMethod(Server, '_ProcessInput', RaiseError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        with self.assertLogs('pyrad', 'ERROR'):
            self.assertRaises(MockFinished, self.server.Run)

    def testRunRunsProcessInput(self):
        MockClassMethod(Server, '_ProcessInput')
        self.server.authfds = fd = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.Run)
        self.assertEqual(self.server.called, [('_ProcessInput', (fd[0],), {})])


if not hasattr(select, 'poll'):
    del SocketTests
    del ServerRunTests
