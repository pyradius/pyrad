import select
import socket
import unittest
from pyrad.server import RemoteHost
from pyrad.server import Server
from pyrad.server import PacketError
from pyrad.tests.mock import MockFinished
from pyrad.tests.mock import MockPoll
from pyrad.tests.mock import MockSocket
from pyrad.tests.mock import MockClassMethod
from pyrad.tests.mock import UnmockClassMethods
from pyrad.packet import AccessRequest
from pyrad.packet import AccountingRequest


class TrivialObject:
    """dummy object"""


class MockFd:
    data = object()
    source = object()

    def __init__(self, fd=0):
        self.fd=fd

    def fileno(self):
        return self.fd

    def recvfrom(self, size):
        self.size=size
        return (self.data, self.source)



class RemoteHostTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host=RemoteHost("address", "secret", "name", "authport", "acctport")
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")


    def testNamedConstruction(self):
        host=RemoteHost(address="address", secret="secret", name="name",
               authport="authport", acctport="acctport")
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")


class ServerConstructiontests(unittest.TestCase):
    def testSimpleConstruction(self):
        server=Server()
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, 1812)
        self.assertEqual(server.acctport, 1813)
        self.assertEqual(server.hosts, {})


    def testParameterOrder(self):
        server=Server([], "authport", "acctport", "hosts", "dict")
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, "authport")
        self.assertEqual(server.acctport, "acctport")
        self.assertEqual(server.dict, "dict")


    def testBindDuringConstruction(self):
        def BindToAddress(self, addr):
            self.bound.append(addr)
        bta=Server.BindToAddress
        Server.BindToAddress=BindToAddress

        Server.bound=[]
        server=Server(["one", "two", "three"])
        self.assertEqual(server.bound, ["one", "two", "three"])
        del Server.bound

        Server.BindToAddress=bta



class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket=socket.socket
        socket.socket=MockSocket
        self.server=Server()


    def tearDown(self):
        socket.socket=self.orgsocket


    def testBind(self):
        self.server.BindToAddress("192.168.13.13")
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address,
                ("192.168.13.13", 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address,
                ("192.168.13.13", 1813))


    def testGrabPacket(self):
        def gen(data):
            res=TrivialObject()
            res.data=data
            return res


        fd=MockFd()
        fd.source=object()
        pkt=self.server._GrabPacket(gen, fd)
        self.failUnless(isinstance(pkt, TrivialObject))
        self.failUnless(pkt.fd is fd)
        self.failUnless(pkt.source is fd.source)
        self.failUnless(pkt.data is fd.data)


    def testPrepareSocketNoFds(self):
        self.server._poll=MockPoll()
        self.server._PrepareSockets()

        self.assertEqual(self.server._poll.registry, [])
        self.assertEqual(self.server._realauthfds, [])
        self.assertEqual(self.server._realacctfds, [])


    def testPrepareSocketAuthFds(self):
        self.server._poll=MockPoll()
        self.server._fdmap={}
        self.server.authfds=[MockFd(12), MockFd(14)]
        self.server._PrepareSockets()

        self.assertEqual(self.server._fdmap.keys(), [12, 14])
        self.assertEqual(self.server._poll.registry,
                [(12, select.POLLIN|select.POLLPRI|select.POLLERR),
                 (14, select.POLLIN|select.POLLPRI|select.POLLERR)])


    def testPrepareSocketAcctFds(self):
        self.server._poll=MockPoll()
        self.server._fdmap={}
        self.server.acctfds=[MockFd(12), MockFd(14)]
        self.server._PrepareSockets()

        self.assertEqual(self.server._fdmap.keys(), [12, 14])
        self.assertEqual(self.server._poll.registry,
                [(12, select.POLLIN|select.POLLPRI|select.POLLERR),
                 (14, select.POLLIN|select.POLLPRI|select.POLLERR)])


class AuthPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server=Server()
        self.server.hosts["host"]=TrivialObject()
        self.server.hosts["host"].secret="supersecret"
        self.packet=TrivialObject()
        self.packet.code=AccessRequest
        self.packet.source=("host", "port")


    def testHandleAuthPacketUnknownHost(self):
        self.packet.source=("stranger", "port")
        try:
            self.server._HandleAuthPacket(self.packet)
        except PacketError, e:
            self.failUnless("unknown host" in str(e))
        else:
            self.fail()


    def testHandleAuthPacketWrongPort(self):
        self.packet.code=AccountingRequest
        try:
            self.server._HandleAuthPacket(self.packet)
        except PacketError, e:
            self.failUnless("port" in str(e))
        else:
            self.fail()


    def testHandleAuthPacket(self):
        def HandleAuthPacket(self, pkt):
            self.handled=pkt
        hap=Server.HandleAuthPacket
        Server.HandleAuthPacket=HandleAuthPacket

        self.server._HandleAuthPacket(self.packet)
        self.failUnless(self.server.handled is self.packet)

        Server.HandleAuthPacket=hap



class AcctPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server=Server()
        self.server.hosts["host"]=TrivialObject()
        self.server.hosts["host"].secret="supersecret"
        self.packet=TrivialObject()
        self.packet.code=AccountingRequest
        self.packet.source=("host", "port")


    def testHandleAcctPacketUnknownHost(self):
        self.packet.source=("stranger", "port")
        try:
            self.server._HandleAcctPacket(self.packet)
        except PacketError, e:
            self.failUnless("unknown host" in str(e))
        else:
            self.fail()


    def testHandleAcctPacketWrongPort(self):
        self.packet.code=AccessRequest
        try:
            self.server._HandleAcctPacket(self.packet)
        except PacketError, e:
            self.failUnless("port" in str(e))
        else:
            self.fail()


    def testHandleAcctPacket(self):
        def HandleAcctPacket(self, pkt):
            self.handled=pkt
        hap=Server.HandleAcctPacket
        Server.HandleAcctPacket=HandleAcctPacket

        self.server._HandleAcctPacket(self.packet)
        self.failUnless(self.server.handled is self.packet)

        Server.HandleAcctPacket=hap


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server=Server()


    def testCreateReplyPacket(self):
        class TrivialPacket:
            source=object()
            def CreateReply(self, **kw):
                reply=TrivialObject()
                reply.kw=kw
                return reply

        reply=self.server.CreateReplyPacket(TrivialPacket(),
                one="one", two="two")
        self.failUnless(isinstance(reply, TrivialObject))
        self.failUnless(reply.source is TrivialPacket.source)
        self.assertEqual(reply.kw, dict(one="one", two="two"))


    def testAuthProcessInput(self):
        marker=object()
        def MockGrabPacket(self, pktgen, fd):
            self.grabbed=(pktgen, fd)
            return marker
        def MockHandleAuthPacket(self, pkt):
            self.handled=pkt

        fd=MockFd(1)
        self.server._realauthfds=[1]
        originals=(Server._GrabPacket, Server._HandleAuthPacket)
        Server._GrabPacket=MockGrabPacket
        Server._HandleAuthPacket=MockHandleAuthPacket

        self.server._ProcessInput(fd)
        self.failUnless(self.server.grabbed[1] is fd)
        self.failUnless(self.server.handled is marker)

        (Server._GrabPacket, Server._HandleAuthPacket)=originals


    def testAcctProcessInput(self):
        marker=object()
        def MockGrabPacket(self, pktgen, fd):
            self.grabbed=(pktgen, fd)
            return marker
        def MockHandleAcctPacket(self, pkt):
            self.handled=pkt

        fd=MockFd(1)
        self.server._realauthfds=[]
        self.server._realacctfds=[1]
        originals=(Server._GrabPacket, Server._HandleAcctPacket)
        Server._GrabPacket=MockGrabPacket
        Server._HandleAcctPacket=MockHandleAcctPacket

        self.server._ProcessInput(fd)
        self.failUnless(self.server.grabbed[1] is fd)
        self.failUnless(self.server.handled is marker)

        (Server._GrabPacket, Server._HandleAcctPacket)=originals


class ServerRunTests(unittest.TestCase):
    def setUp(self):
        self.server=Server()
        self.origpoll=select.poll
        select.poll=MockPoll

    def tearDown(self):
        MockPoll.ressults=[]
        select.poll=self.origpoll
        UnmockClassMethods(Server)


    def testRunInitializes(self):
        MockClassMethod(Server, "_PrepareSockets")
        self.assertRaises(MockFinished, self.server.Run)
        self.assertEqual(self.server.called, [("_PrepareSockets", (), {})])
        self.failUnless(isinstance(self.server._fdmap, dict))
        self.failUnless(isinstance(self.server._poll, MockPoll))


    def testRunIgnoresPollWeirdness(self):

        MockPoll.results=(0, select.POLLERR)


