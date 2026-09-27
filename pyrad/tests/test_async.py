"""Tests of the asyncio client and server, running against each other on
the loopback interface."""
import asyncio
import contextlib
import datetime
import logging
import socket
import unittest
from io import StringIO
from unittest import mock

from pyrad import packet
from pyrad.client_async import ClientAsync, DatagramProtocolClient
from pyrad.dictionary import Dictionary
from pyrad.server import RemoteHost
from pyrad.server_async import DatagramProtocolServer, ServerAsync, ServerType

SECRET = b'secret'
PASSWORD = 'password'
LOCALHOST = '127.0.0.1'

DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE User-Password         2  string
ATTRIBUTE Reply-Message         18 string
ATTRIBUTE Acct-Status-Type      40 integer
ATTRIBUTE Acct-Session-Id       44 string
ATTRIBUTE Tunnel-Password       69 string has_tag,encrypt=2
ATTRIBUTE Message-Authenticator 80 octets
VALUE     Acct-Status-Type      Start 1
'''


def free_ports(count):
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind((LOCALHOST, 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


@contextlib.contextmanager
def without_reuse_port():
    """Simulate a platform without SO_REUSEPORT, e.g. Windows."""
    reuse_port = getattr(socket, 'SO_REUSEPORT', None)
    if reuse_port is not None:
        del socket.SO_REUSEPORT
    try:
        yield
    finally:
        if reuse_port is not None:
            socket.SO_REUSEPORT = reuse_port


class RadiusServer(ServerAsync):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = []

    def handle_auth_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        reply = self.CreateReplyPacket(pkt, Reply_Message='hello')
        if pkt.PwDecrypt(pkt[2][0]) == PASSWORD:
            reply.code = packet.AccessAccept
            reply['Tunnel-Password:1'] = 'a-tunnel-password-longer-than-16'
        else:
            reply.code = packet.AccessReject
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        protocol.send_response(self.CreateReplyPacket(pkt), addr)

    def handle_coa_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        protocol.send_response(self.CreateReplyPacket(pkt), addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):
        self.received.append(pkt)
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.DisconnectACK
        protocol.send_response(reply, addr)


class AsyncRoundTripTests(unittest.TestCase):
    """ClientAsync sending requests to ServerAsync."""

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

    def run_with(self, test, hosts=None, client_secret=SECRET, **server_args):
        """Run test(client, server) with a started server and client."""
        if hosts is None:
            hosts = {LOCALHOST: RemoteHost(LOCALHOST, SECRET, 'localhost')}

        async def run():
            loop = asyncio.get_running_loop()
            server = RadiusServer(hosts=hosts, dictionary=self.dict, loop=loop,
                                **self.ports, **server_args)
            await server.initialize_transports(enable_auth=True, enable_acct=True,
                                               enable_coa=True, addresses=[LOCALHOST])
            client = ClientAsync(server=LOCALHOST, secret=client_secret, dict=self.dict,
                                 loop=loop, timeout=0.5, retries=1, **self.ports)
            await client.initialize_transports(enable_auth=True, enable_acct=True,
                                               enable_coa=True)
            try:
                return await test(client, server)
            finally:
                await client.deinitialize_transports()
                await server.deinitialize_transports()

        return asyncio.run(run())

    def auth_request(self, client, password=PASSWORD):
        req = client.CreateAuthPacket(User_Name='alice')
        req['User-Password'] = req.PwCrypt(password)
        return req

    def testAccessAccept(self):
        async def test(client, server):
            client.enforce_ma = True
            return await client.SendPacket(self.auth_request(client))
        reply = self.run_with(test)
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply['Reply-Message'], ['hello'])
        # salt encrypted with the request authenticator
        self.assertEqual(reply['Tunnel-Password:1'], ['a-tunnel-password-longer-than-16'])

    def testAccessReject(self):
        async def test(client, server):
            return await client.SendPacket(self.auth_request(client, 'wrong'))
        self.assertEqual(self.run_with(test).code, packet.AccessReject)

    def testAccounting(self):
        async def test(client, server):
            req = client.CreateAcctPacket(User_Name='alice', Acct_Status_Type='Start',
                                          Acct_Session_Id='1')
            return await client.SendPacket(req)
        reply = self.run_with(test)
        self.assertEqual(reply.code, packet.AccountingResponse)

    def testCoA(self):
        async def test(client, server):
            return await client.SendPacket(client.CreateCoAPacket(User_Name='alice'))
        self.assertEqual(self.run_with(test).code, packet.CoAACK)

    def testDisconnect(self):
        async def test(client, server):
            req = client.CreateCoAPacket(code=packet.DisconnectRequest, User_Name='alice')
            return await client.SendPacket(req)
        self.assertEqual(self.run_with(test).code, packet.DisconnectACK)

    def testPacketVerificationFailure(self):
        # by default the server drops requests with an invalid request
        # authenticator
        async def test(client, server):
            with self.assertRaises(TimeoutError):
                await client.SendPacket(client.CreateAcctPacket(User_Name='alice'))
            with self.assertRaises(TimeoutError):
                await client.SendPacket(client.CreateCoAPacket(User_Name='alice'))
            return server.received
        self.assertEqual(self.run_with(test, client_secret=b'wrong'), [])

    def testPacketVerificationDisabled(self):
        async def test(client, server):
            # the client drops the reply, which is signed with another secret
            with self.assertRaises(TimeoutError):
                await client.SendPacket(client.CreateAcctPacket(User_Name='alice'))
            return server.received
        received = self.run_with(test, client_secret=b'wrong', enable_pkt_verify=False)
        self.assertNotEqual(received, [])

    def testUnknownHost(self):
        async def test(client, server):
            with self.assertRaises(TimeoutError):
                await client.SendPacket(self.auth_request(client))
            return server.received
        self.assertEqual(self.run_with(test, hosts={}), [])

    def testTransportsAreNotBoundTwice(self):
        async def test(client, server):
            protocols = list(server.auth_protocols)
            await server.initialize_transports(enable_auth=True, addresses=[LOCALHOST])
            await client.initialize_transports(enable_auth=True)
            self.assertEqual(server.auth_protocols, protocols)
            return await client.SendPacket(self.auth_request(client))
        self.assertEqual(self.run_with(test).code, packet.AccessAccept)


class AsyncClientTests(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict,
                                  loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def testNoTransportsSelected(self):
        with self.assertRaises(Exception):
            self.loop.run_until_complete(self.client.initialize_transports())

    def testTransportNotInitialized(self):
        self.assertRaises(Exception, self.client.CreateAuthPacket)
        self.assertRaises(Exception, self.client.CreateAcctPacket)
        self.assertRaises(Exception, self.client.CreateCoAPacket)
        for pkt in (packet.AuthPacket(), packet.AcctPacket(), packet.CoAPacket()):
            self.assertRaises(Exception, self.client.SendPacket, pkt)

    def testUnsupportedPacket(self):
        self.assertRaises(Exception, self.client.SendPacket, packet.Packet())

    def testCreatePacket(self):
        self.assertRaises(Exception, self.client.CreatePacket, None)
        pkt = self.client.CreatePacket(id=10, User_Name='alice')
        self.assertEqual((pkt.id, pkt['User-Name']), (10, ['alice']))
        # 0 is a valid id
        self.assertEqual(self.client.CreatePacket(id=0).id, 0)

    def testPacketIdOfPendingRequestIsSkipped(self):
        # ids wrapped around to the id of a still pending request, and
        # sending the request failed with 'Packet with id N already present'
        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol()
            pending = packet.AuthPacket(id=protocol.create_id(), secret=SECRET,
                                        dict=self.dict)
            protocol.send_packet(pending, loop.create_future())
            # 255 requests which are answered (here: cancelled)
            for _ in range(255):
                future = loop.create_future()
                protocol.send_packet(packet.AuthPacket(id=protocol.create_id(),
                                                       secret=SECRET, dict=self.dict),
                                     future)
                future.cancel()
                await asyncio.sleep(0)
            self.assertEqual(list(protocol.pending_requests), [pending.id])
            req = packet.AuthPacket(id=protocol.create_id(), secret=SECRET, dict=self.dict)
            self.assertNotEqual(req.id, pending.id)
            protocol.send_packet(req, loop.create_future())
        self.loop.run_until_complete(test())

    def testAllPacketIdsPending(self):
        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol()
            for _ in range(256):
                protocol.send_packet(packet.AuthPacket(id=protocol.create_id(),
                                                       secret=SECRET, dict=self.dict),
                                     loop.create_future())
            self.assertEqual(sorted(protocol.pending_requests), list(range(256)))
            with self.assertRaisesRegex(Exception, 'No free packet id'):
                protocol.create_id()
            # an id becomes free again
            protocol.pending_requests[42]['future'].cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.create_id(), 42)
        self.loop.run_until_complete(test())

    def testInvalidReplies(self):
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            protocol = self.client.protocol_auth
            req = self.client.CreateAuthPacket(User_Name='alice')
            future = self.client.SendPacket(req)
            # garbage, a reply to an unknown request and a forged reply
            protocol.datagram_received(b'garbage', (LOCALHOST, 1812))
            other = packet.AuthPacket(code=packet.AccessAccept, id=(req.id + 1) % 256,
                                      secret=SECRET, authenticator=16 * b'\x00')
            protocol.datagram_received(other.ReplyPacket(), (LOCALHOST, 1812))
            forged = req.CreateReply()
            forged.secret = b'wrong'
            protocol.datagram_received(forged.ReplyPacket(), (LOCALHOST, 1812))
            self.assertFalse(future.done())
            self.assertIn(req.id, protocol.pending_requests)
            self.assertEqual(str(protocol), f'DatagramProtocolClient(server={LOCALHOST}, port=1812)')
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testDefaultLoop(self):
        async def test():
            client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict)
            return client.loop is asyncio.get_running_loop()
        self.assertTrue(asyncio.run(test()))

    def testLoopResolvedWhenUsed(self):
        # created outside of a running loop (asyncio.get_event_loop() raises
        # there since Python 3.14), and used with more than one loop
        client = ClientAsync(server=LOCALHOST, secret=SECRET, dict=self.dict)

        async def test():
            return client.loop is asyncio.get_running_loop()
        self.assertTrue(asyncio.run(test()))
        self.assertTrue(asyncio.run(test()))
        client.loop = self.loop
        self.assertIs(client.loop, self.loop)

    def testDuplicatePacketId(self):
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            req = self.client.CreateAuthPacket(User_Name='alice')
            self.client.SendPacket(req)
            with self.assertRaises(Exception):
                self.client.protocol_auth.send_packet(req, self.loop.create_future())
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testLocalAddress(self):
        ports = dict(zip(('local_auth_port', 'local_acct_port', 'local_coa_port'),
                         free_ports(3)))

        async def test():
            await self.client.initialize_transports(enable_auth=True, enable_acct=True,
                                                    enable_coa=True, local_addr=LOCALHOST,
                                                    **ports)
            bound = [protocol.transport.get_extra_info('sockname')
                     for protocol in (self.client.protocol_auth, self.client.protocol_acct,
                                      self.client.protocol_coa)]
            await self.client.deinitialize_transports()
            return bound
        self.assertEqual(self.loop.run_until_complete(test()),
                         [(LOCALHOST, ports['local_auth_port']),
                          (LOCALHOST, ports['local_acct_port']),
                          (LOCALHOST, ports['local_coa_port'])])

    def testLocalAddressWithoutPort(self):
        # local_addr used to be ignored without a local port
        async def test():
            loop = asyncio.get_running_loop()
            with mock.patch.object(loop, 'create_datagram_endpoint',
                                   wraps=loop.create_datagram_endpoint) as connect:
                await self.client.initialize_transports(enable_auth=True, enable_acct=True,
                                                        local_addr=LOCALHOST,
                                                        local_acct_port=free_ports(1)[0])
            await self.client.deinitialize_transports()
            return connect.call_args_list
        calls = self.loop.run_until_complete(test())
        self.assertEqual(calls[1].kwargs['local_addr'], (LOCALHOST, 0))
        self.assertEqual(calls[0].kwargs['local_addr'][0], LOCALHOST)
        self.assertNotEqual(calls[0].kwargs['local_addr'][1], 0)

    def testWithoutReusePort(self):
        # reuse_port=True raised ValueError without SO_REUSEPORT
        async def test():
            with without_reuse_port():
                await self.client.initialize_transports(enable_auth=True)
            self.assertIsNotNone(self.client.protocol_auth.transport)
            await self.client.deinitialize_transports()
        self.loop.run_until_complete(test())

    def testInitializeFailureCanBeRetried(self):
        # a transport which couldn't be opened used to stay registered, so a
        # retry was skipped and SendPacket failed with AttributeError
        async def test():
            loop = asyncio.get_running_loop()
            connect = loop.create_datagram_endpoint

            async def fail_auth(protocol, **kwargs):
                if protocol.port == 1812:
                    raise OSError('bind failed')
                return await connect(protocol, **kwargs)
            with mock.patch.object(loop, 'create_datagram_endpoint', fail_auth):
                with self.assertRaises(OSError):
                    await self.client.initialize_transports(enable_auth=True,
                                                            enable_acct=True)
            self.assertIsNone(self.client.protocol_auth)
            self.assertRaises(Exception, self.client.CreateAuthPacket)
            # the transport opened successfully is kept
            self.assertIsNotNone(self.client.protocol_acct.transport)
            await self.client.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertIsNotNone(self.client.protocol_auth.transport)
            future = self.client.SendPacket(self.client.CreateAuthPacket(User_Name='alice'))
            await self.client.deinitialize_transports()
            with self.assertRaises(ConnectionAbortedError):
                await future
        self.loop.run_until_complete(test())

    def testRetryTimeout(self):
        timeout = 0.3

        async def test():
            loop = asyncio.get_running_loop()
            protocol = DatagramProtocolClient(LOCALHOST, 1812, mock.Mock(), self.client,
                                              retries=1, timeout=timeout)
            sent = []
            protocol.transport = mock.Mock()
            protocol.transport.sendto.side_effect = lambda data: sent.append(loop.time())
            handler = asyncio.ensure_future(protocol.__timeout_handler__())
            # send while the timeout handler is sleeping
            await asyncio.sleep(timeout / 2)
            future = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 future)
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(future, 5 * timeout)
            sent.append(loop.time())
            handler.cancel()
            await handler
            self.assertEqual(protocol.pending_requests, {})
            return sent
        (request, retry, failed) = self.loop.run_until_complete(test())
        # a request is retried and fails only after the timeout has passed
        self.assertGreaterEqual(retry - request, timeout * 0.9)
        self.assertGreaterEqual(failed - retry, timeout * 0.9)
        self.assertLess(failed - request, 3 * timeout)

    def mock_protocol(self, timeout=0.2, retries=0):
        protocol = DatagramProtocolClient(LOCALHOST, 1812, mock.Mock(), self.client,
                                          retries=retries, timeout=timeout)
        protocol.transport = mock.Mock()
        return protocol

    def run_with_clock_step(self, step, timeout):
        """Send a request, step the wall clock and run the timeout handler
        for a moment. Return the future of the request."""
        class SteppedDatetime(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.datetime.now(tz) + step

        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol(timeout=timeout)
            future = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 future)
            # the client used to measure timeouts with the wall clock
            with mock.patch('pyrad.client_async.datetime', SteppedDatetime, create=True):
                handler = asyncio.ensure_future(protocol.__timeout_handler__())
                await asyncio.wait([future], timeout=1)
            handler.cancel()
            await handler
            return future
        return self.loop.run_until_complete(test())

    def testClockStepBackwards(self):
        # the request used to time out only after the clock caught up
        future = self.run_with_clock_step(-datetime.timedelta(hours=1), timeout=0.2)
        self.assertTrue(future.done())
        self.assertIsInstance(future.exception(), TimeoutError)

    def testClockStepForwards(self):
        # the request used to time out right away
        future = self.run_with_clock_step(datetime.timedelta(hours=1), timeout=30)
        self.assertFalse(future.done())
        future.cancel()

    def testCancelledRequest(self):
        # a request cancelled by the caller (e.g. with asyncio.wait_for) used
        # to kill the timeout handler, so later requests never timed out
        async def test():
            loop = asyncio.get_running_loop()
            protocol = self.mock_protocol()
            handler = asyncio.ensure_future(protocol.__timeout_handler__())
            cancelled = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 cancelled)
            cancelled.cancel()
            await asyncio.sleep(0)
            self.assertEqual(protocol.pending_requests, {})
            future = loop.create_future()
            protocol.send_packet(packet.AuthPacket(id=2, secret=SECRET, dict=self.dict),
                                 future)
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(future, 2)
            self.assertFalse(handler.done())
            handler.cancel()
            await handler
        self.loop.run_until_complete(test())

    def testReplyForCancelledRequest(self):
        async def test():
            protocol = self.mock_protocol()
            req = packet.AuthPacket(id=1, secret=SECRET, dict=self.dict)
            future = asyncio.get_running_loop().create_future()
            protocol.send_packet(req, future)
            future.cancel()
            protocol.datagram_received(req.CreateReply().ReplyPacket(), (LOCALHOST, 1812))
            protocol.logger.error.assert_not_called()
            self.assertEqual(protocol.pending_requests, {})
        self.loop.run_until_complete(test())

    def testEncodeErrorIsNotPending(self):
        async def test():
            protocol = self.mock_protocol()
            req = packet.AuthPacket(id=1, secret=SECRET, dict=self.dict)
            req[1] = [300 * b'x']
            with self.assertRaises(Exception):
                protocol.send_packet(req, asyncio.get_running_loop().create_future())
            self.assertEqual(protocol.pending_requests, {})
        self.loop.run_until_complete(test())

    def testRetrySendError(self):
        async def test():
            protocol = self.mock_protocol(retries=1)
            handler = asyncio.ensure_future(protocol.__timeout_handler__())
            future = asyncio.get_running_loop().create_future()
            protocol.send_packet(packet.AuthPacket(id=1, secret=SECRET, dict=self.dict),
                                 future)
            protocol.transport.sendto.side_effect = OSError('send failed')
            with self.assertRaises(OSError):
                await asyncio.wait_for(future, 2)
            self.assertFalse(handler.done())
            handler.cancel()
            await handler
        self.loop.run_until_complete(test())

    def testCloseTransportFailsPendingRequests(self):
        async def test():
            await self.client.initialize_transports(enable_auth=True)
            future = self.client.SendPacket(self.client.CreateAuthPacket(User_Name='alice'))
            await self.client.deinitialize_transports()
            with self.assertRaises(ConnectionAbortedError):
                await asyncio.wait_for(future, 2)
        self.loop.run_until_complete(test())

    def testProtocol(self):
        logger = mock.Mock()
        protocol = DatagramProtocolClient(LOCALHOST, 1812, logger, self.client)
        protocol.error_received(OSError('error'))
        logger.error.assert_called_once()
        protocol.connection_lost(OSError('lost'))
        logger.warning.assert_called_once()
        protocol.connection_lost(None)
        logger.info.assert_called_once()


class AsyncServerProtocolTests(unittest.TestCase):
    """Packets dropped by DatagramProtocolServer."""

    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.handled = []
        self.server = type('Server', (), {})()
        self.server.dict = self.dict
        self.server.debug = False
        self.server.enable_pkt_verify = True
        self.server.enforce_ma = False
        self.hosts = {'0.0.0.0': RemoteHost('0.0.0.0', SECRET, 'any')}

    def receive(self, server_type, pkt, source=(LOCALHOST, 1812)):
        protocol = DatagramProtocolServer(
            LOCALHOST, 1812, logging.getLogger('pyrad-test'), self.server, server_type,
            self.hosts, lambda protocol, req, addr: self.handled.append(req))
        data = pkt if isinstance(pkt, bytes) else pkt.RequestPacket()
        protocol.datagram_received(data, source)
        return protocol

    def testDefaultHost(self):
        self.receive(ServerType.Auth, packet.AuthPacket(secret=SECRET, dict=self.dict,
                                                        User_Name='alice'))
        self.assertEqual(len(self.handled), 1)

    def testMappedAddress(self):
        # IPv4 client of a dual stack server bound to '::'
        self.hosts = {LOCALHOST: RemoteHost(LOCALHOST, SECRET, 'local')}
        self.receive(ServerType.Auth, packet.AuthPacket(secret=SECRET, dict=self.dict,
                                                        User_Name='alice'),
                     source=('::ffff:' + LOCALHOST, 1812, 0, 0))
        self.assertEqual(len(self.handled), 1)
        self.assertEqual(self.handled[0].secret, SECRET)

    def testGarbage(self):
        self.receive(ServerType.Auth, b'garbage')
        self.assertEqual(self.handled, [])

    def testResponsePacket(self):
        reply = packet.AuthPacket(code=packet.AccessAccept, secret=SECRET,
                                  authenticator=16 * b'\x00')
        self.receive(ServerType.Auth, reply.ReplyPacket())
        self.assertEqual(self.handled, [])

    def testWrongPort(self):
        acct = packet.AcctPacket(secret=SECRET, dict=self.dict)
        auth = packet.AuthPacket(secret=SECRET, dict=self.dict)
        self.receive(ServerType.Auth, acct)
        self.receive(ServerType.Acct, auth)
        self.receive(ServerType.Coa, auth)
        self.assertEqual(self.handled, [])

    def testInvalidCoARequest(self):
        req = packet.CoAPacket(secret=b'wrong', dict=self.dict)
        self.receive(ServerType.Coa, req)
        self.server.debug = True
        self.receive(ServerType.Coa, req)
        self.assertEqual(self.handled, [])

    def testProtocol(self):
        protocol = self.receive(ServerType.Auth, b'garbage')
        self.assertEqual(str(protocol), f'DatagramProtocolServer(ip={LOCALHOST}, port=1812)')
        self.assertIs(protocol(), protocol)
        protocol.error_received(OSError('error'))
        protocol.connection_lost(None)
        protocol.connection_lost(OSError('lost'))


class AsyncServerTests(unittest.TestCase):
    def testNoTransportsSelected(self):
        loop = asyncio.new_event_loop()
        server = RadiusServer(loop=loop)
        with self.assertRaises(Exception):
            loop.run_until_complete(server.initialize_transports())
        loop.close()

    def testRequestHandlerErrors(self):
        loop = asyncio.new_event_loop()
        server = RadiusServer(loop=loop)
        protocol = type('Protocol', (), {'ip': LOCALHOST, 'port': 1812})()
        # unexpected request type and exception in a handler are logged
        protocol.server_type = ServerType.Coa
        server.__request_handler__(protocol, packet.CoAPacket(code=packet.CoAACK), None)
        protocol.server_type = ServerType.Auth
        for server.debug in (False, True):
            server.__request_handler__(protocol, None, None)
        loop.close()

    def testLoopResolvedWhenUsed(self):
        server = RadiusServer()

        async def test():
            return server.loop is asyncio.get_running_loop()
        self.assertTrue(asyncio.run(test()))
        self.assertTrue(asyncio.run(test()))

    def testDefaultLoopAndAddress(self):
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            server = RadiusServer(**ports)
            self.assertIs(server.loop, asyncio.get_running_loop())
            await server.initialize_transports(enable_acct=True, enable_coa=True)
            protocols = server.acct_protocols + server.coa_protocols
            self.assertEqual([proto.ip for proto in protocols], [LOCALHOST, LOCALHOST])
            # already bound transports are not bound again
            await server.initialize_transports(enable_acct=True, enable_coa=True)
            self.assertEqual(server.acct_protocols + server.coa_protocols, protocols)
            await server.deinitialize_transports()
        asyncio.run(test())

    def testWithoutReusePort(self):
        # reuse_port=True raised ValueError without SO_REUSEPORT
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            server = RadiusServer(**ports)
            with without_reuse_port():
                await server.initialize_transports(enable_auth=True)
            self.assertIsNotNone(server.auth_protocols[0].transport)
            await server.deinitialize_transports()
        asyncio.run(test())

    def testInitializeFailureCanBeRetried(self):
        # a transport which couldn't be bound used to stay registered, so a
        # retry was a no-op and nothing listened
        ports = dict(zip(('auth_port', 'acct_port', 'coa_port'), free_ports(3)))

        async def test():
            loop = asyncio.get_running_loop()
            server = RadiusServer(loop=loop, **ports)
            connect = loop.create_datagram_endpoint

            async def fail_auth(protocol, **kwargs):
                if protocol.server_type == ServerType.Auth:
                    raise OSError('bind failed')
                return await connect(protocol, **kwargs)
            with mock.patch.object(loop, 'create_datagram_endpoint', fail_auth):
                with self.assertRaises(OSError):
                    await server.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertEqual(server.auth_protocols, [])
            # the transport bound successfully is kept
            self.assertEqual(len(server.acct_protocols), 1)
            await server.initialize_transports(enable_auth=True, enable_acct=True)
            self.assertEqual(len(server.acct_protocols), 1)
            self.assertEqual(len(server.auth_protocols), 1)
            self.assertIsNotNone(server.auth_protocols[0].transport)
            await server.deinitialize_transports()
        asyncio.run(test())
