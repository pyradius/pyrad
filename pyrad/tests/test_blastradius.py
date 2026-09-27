"""BlastRADIUS (CVE-2024-3596) countermeasures, see https://blastradius.fail

The attack forges an Access-Accept from an Access-Reject using a MD5
chosen-prefix collision hidden in Proxy-State attributes. It is prevented
by a Message-Authenticator (HMAC-MD5) in requests and responses.
"""
import asyncio
import hashlib
import logging
import struct
import unittest
from io import StringIO

from pyrad import packet
from pyrad.client import Client
from pyrad.client_async import ClientAsync
from pyrad.dictionary import Dictionary
from pyrad.server import RemoteHost, Server, ServerPacketError
from pyrad.server_async import DatagramProtocolServer, ServerType
from pyrad.tests.test_curved import load_curved

SECRET = b'secret'

# Message-Authenticator is deliberately not defined in this dictionary.
DICTIONARY = '''
ATTRIBUTE User-Name     1  string
ATTRIBUTE User-Password 2  string
ATTRIBUTE Reply-Message 18 string
ATTRIBUTE Proxy-State   33 octets
'''


def attributes(raw):
    """Return the (type, value) attributes of a raw packet."""
    result, data = [], raw[20:]
    while data:
        (key, length) = struct.unpack('!BB', data[:2])
        result.append((key, data[2:length]))
        data = data[length:]
    return result


def forge_response_authenticator(raw, request_authenticator):
    """Recalculate the Response Authenticator of a modified reply, which is
    what the MD5 collision of the BlastRADIUS attack achieves."""
    authenticator = hashlib.md5(raw[:4] + request_authenticator + raw[20:] + SECRET).digest()
    return raw[:4] + authenticator + raw[20:]


class BlastRadiusTestCase(unittest.TestCase):
    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.client = Client(server='127.0.0.1', secret=SECRET, dict=self.dict)

    def request(self, **attrs):
        req = self.client.CreateAuthPacket(code=packet.AccessRequest,
                                           User_Name='alice', **attrs)
        req['User-Password'] = req.PwCrypt('password')
        return req

    def receive(self, req):
        """Decode a request as a server does."""
        return packet.AuthPacket(packet=req.RequestPacket(), secret=SECRET, dict=self.dict)

    def reply(self, req, **attrs):
        """Return the raw reply of a server to the request."""
        reply = self.receive(req).CreateReply(Reply_Message='hello', **attrs)
        return reply.ReplyPacket()

    def verify(self, req, raw, enforce_ma=False):
        return req.VerifyReply(req.CreateReply(packet=raw), raw, enforce_ma=enforce_ma)


class ClientRequestTests(BlastRadiusTestCase):
    def testAccessRequestHasMessageAuthenticatorFirst(self):
        raw = self.request().RequestPacket()
        self.assertEqual(attributes(raw)[0][0], 80)
        self.assertTrue(self.receive(self.request()).verify_message_authenticator())

    def testStatusServerHasMessageAuthenticator(self):
        req = self.client.CreateAuthPacket(code=packet.StatusServer)
        self.assertEqual(attributes(req.RequestPacket())[0][0], 80)

    def testMessageAuthenticatorOptOut(self):
        raw = self.request(message_authenticator=False).RequestPacket()
        self.assertNotIn(80, [key for (key, _) in attributes(raw)])

    def testEapMd5HasSingleMessageAuthenticator(self):
        req = self.request(auth_type='eap-md5')
        keys = [key for (key, _) in attributes(req.RequestPacket())]
        self.assertEqual(keys.count(80), 1)

    def testAsyncClientAddsMessageAuthenticator(self):
        client = ClientAsync(server='127.0.0.1', secret=SECRET, dict=self.dict,
                             loop=asyncio.new_event_loop())
        client.protocol_auth = type('Protocol', (), {'create_id': lambda self: 1})()
        req = client.CreateAuthPacket(User_Name='alice')
        self.assertEqual(attributes(req.RequestPacket())[0][0], 80)
        client.loop.close()


class ServerReplyTests(BlastRadiusTestCase):
    def testReplyHasMessageAuthenticatorFirst(self):
        raw = self.reply(self.request())
        self.assertEqual(attributes(raw)[0][0], 80)

    def testReplyEchoesProxyState(self):
        req = self.request(Proxy_State=[b'first', b'second'])
        raw = self.reply(req)
        proxy_states = [value for (key, value) in attributes(raw) if key == 33]
        self.assertEqual(proxy_states, [b'first', b'second'])

    def testDecodedReplyIsNotModified(self):
        req = self.request(Proxy_State=b'state')
        reply = self.receive(req).CreateReply()
        reply.message_authenticator = False
        del reply[33]
        decoded = req.CreateReply(packet=reply.ReplyPacket())
        self.assertFalse(decoded.message_authenticator)
        self.assertEqual(list(decoded.keys()), [])


class ClientVerifyReplyTests(BlastRadiusTestCase):
    def testReplyWithMessageAuthenticator(self):
        req = self.request()
        self.assertTrue(self.verify(req, self.reply(req), enforce_ma=True))

    def testReplyWithInvalidMessageAuthenticator(self):
        req = self.request()
        raw = bytearray(self.reply(req))
        raw[22] ^= 0xff                     # first byte of Message-Authenticator
        raw = forge_response_authenticator(bytes(raw), req.authenticator)
        self.assertFalse(self.verify(req, raw))
        self.assertFalse(self.verify(req, raw, enforce_ma=True))

    def testReplyWithoutMessageAuthenticator(self):
        req = self.request()
        reply = self.receive(req).CreateReply()
        reply.message_authenticator = False
        raw = reply.ReplyPacket()
        self.assertTrue(self.verify(req, raw))
        self.assertFalse(self.verify(req, raw, enforce_ma=True))

    def testReplyWithInjectedProxyState(self):
        # Proxy-State the client did not send is the signature of the attack
        req = self.request(message_authenticator=False)
        reply = self.receive(req).CreateReply(Proxy_State=b'collision')
        reply.message_authenticator = False
        self.assertFalse(self.verify(req, reply.ReplyPacket()))

    def testReplyWithModifiedProxyState(self):
        req = self.request(Proxy_State=b'state')
        raw = self.reply(req, Proxy_State=b'other')
        self.assertFalse(self.verify(req, raw))

    def testAccountingResponseWithoutMessageAuthenticator(self):
        # enforce_ma only applies to replies to Access-Request and Status-Server
        req = self.client.CreateAcctPacket(User_Name='alice')
        received = packet.AcctPacket(packet=req.RequestPacket(), secret=SECRET, dict=self.dict)
        raw = received.CreateReply().ReplyPacket()
        self.assertTrue(self.verify(req, raw, enforce_ma=True))

    def testCoAAckMessageAuthenticator(self):
        req = packet.CoAPacket(secret=SECRET, dict=self.dict, User_Name='alice',
                               message_authenticator=True)
        received = packet.CoAPacket(packet=req.RequestPacket(), secret=SECRET, dict=self.dict)
        self.assertTrue(received.verify_message_authenticator())
        reply = received.CreateReply()
        reply.add_message_authenticator()
        raw = reply.ReplyPacket()
        decoded = req.CreateReply(packet=raw)
        self.assertTrue(decoded.verify_message_authenticator(
            original_authenticator=req.authenticator, original_code=req.code))
        self.assertTrue(req.VerifyReply(decoded, raw, enforce_ma=True))


class AcctStatusServerTests(BlastRadiusTestCase):
    """Status-Server sent to the accounting port (RFC 5997 section 3)."""

    def status_server(self, **attrs):
        return self.client.CreateAcctPacket(code=packet.StatusServer, **attrs)

    def testRequestHasValidMessageAuthenticator(self):
        req = self.status_server()
        raw = req.RequestPacket()
        self.assertEqual(attributes(raw)[0][0], 80)
        received = packet.AcctPacket(packet=raw, secret=SECRET, dict=self.dict)
        self.assertTrue(received.verify_message_authenticator())
        self.assertTrue(received.VerifyAcctRequest())

    def testRequestHasRandomAuthenticator(self):
        first = self.status_server().RequestPacket()
        second = self.status_server().RequestPacket()
        self.assertNotEqual(first[4:20], second[4:20])
        accounting_style = hashlib.md5(first[:4] + 16 * b'\x00' + first[20:] + SECRET).digest()
        self.assertNotEqual(first[4:20], accounting_style)

    def testRequestKeepsAuthenticator(self):
        req = self.status_server()
        raw = req.RequestPacket()
        self.assertEqual(raw[4:20], req.authenticator)
        self.assertEqual(req.RequestPacket()[4:20], raw[4:20])

    def testRequestMessageAuthenticatorOptOut(self):
        raw = self.status_server(message_authenticator=False).RequestPacket()
        self.assertNotIn(80, [key for (key, _) in attributes(raw)])

    def testTamperedRequest(self):
        raw = self.status_server(User_Name='alice').RequestPacket()
        received = packet.AcctPacket(packet=raw[:-1] + b'X', secret=SECRET, dict=self.dict)
        self.assertFalse(received.verify_message_authenticator())
        self.assertFalse(received.VerifyAcctRequest())

    def testRequestWithoutMessageAuthenticatorFailsVerification(self):
        raw = self.status_server(message_authenticator=False).RequestPacket()
        received = packet.AcctPacket(packet=raw, secret=SECRET, dict=self.dict)
        self.assertFalse(received.VerifyAcctRequest())

    def testReply(self):
        req = self.status_server()
        received = packet.AcctPacket(packet=req.RequestPacket(), secret=SECRET, dict=self.dict)
        raw = received.CreateReply(Reply_Message='hello').ReplyPacket()
        self.assertEqual(attributes(raw)[0][0], 80)
        self.assertTrue(self.verify(req, raw, enforce_ma=True))
        decoded = req.CreateReply(packet=raw)
        self.assertTrue(decoded.verify_message_authenticator(
            original_authenticator=req.authenticator, original_code=req.code))

    def testForgedReply(self):
        req = self.status_server()
        received = packet.AcctPacket(packet=req.RequestPacket(), secret=SECRET, dict=self.dict)
        raw = received.CreateReply(Reply_Message='hello').ReplyPacket()
        forged = forge_response_authenticator(raw.replace(b'hello', b'world'), req.authenticator)
        self.assertFalse(self.verify(req, forged))


class ServerRequestTests(BlastRadiusTestCase):
    def setUp(self):
        super().setUp()
        self.handled = []
        self.server = Server(dict=self.dict, hosts={
            '127.0.0.1': RemoteHost('127.0.0.1', SECRET, 'localhost')})
        self.server.HandleAuthPacket = self.handled.append

    def handle(self, req):
        pkt = self.server.CreateAuthPacket(packet=req.RequestPacket())
        pkt.source = ('127.0.0.1', 1812)
        self.server._HandleAuthPacket(pkt)

    def testValidMessageAuthenticator(self):
        self.handle(self.request())
        self.assertEqual(len(self.handled), 1)

    def testInvalidMessageAuthenticator(self):
        req = self.request()
        req.RequestPacket()
        req.message_authenticator = False           # keep the stale value
        req['User-Name'] = 'mallory'
        self.assertRaises(ServerPacketError, self.handle, req)
        self.assertEqual(self.handled, [])

    def testMissingMessageAuthenticator(self):
        self.handle(self.request(message_authenticator=False))
        self.assertEqual(len(self.handled), 1)

        self.server.enforce_ma = True
        self.assertRaises(ServerPacketError, self.handle,
                          self.request(message_authenticator=False))
        self.assertEqual(len(self.handled), 1)


class AsyncServerRequestTests(BlastRadiusTestCase):
    def setUp(self):
        super().setUp()
        self.handled = []
        self.server = type('Server', (), {})()
        self.server.dict = self.dict
        self.server.debug = False
        self.server.enable_pkt_verify = False
        self.server.enforce_ma = False
        self.protocol = DatagramProtocolServer(
            '127.0.0.1', 1812, logging.getLogger('pyrad-test'), self.server,
            ServerType.Auth, {'127.0.0.1': RemoteHost('127.0.0.1', SECRET, 'localhost')},
            lambda protocol, req, addr: self.handled.append(req))

    def handle(self, req):
        self.protocol.datagram_received(req.RequestPacket(), ('127.0.0.1', 1812))

    def testValidMessageAuthenticator(self):
        self.handle(self.request())
        self.assertEqual(len(self.handled), 1)

    def testInvalidMessageAuthenticator(self):
        req = self.request()
        req.RequestPacket()
        req.message_authenticator = False
        req['User-Name'] = 'mallory'
        self.handle(req)
        self.assertEqual(self.handled, [])

    def testMissingMessageAuthenticator(self):
        self.handle(self.request(message_authenticator=False))
        self.assertEqual(len(self.handled), 1)

        self.server.enforce_ma = True
        self.handle(self.request(message_authenticator=False))
        self.assertEqual(len(self.handled), 1)


class CurvedServerRequestTests(BlastRadiusTestCase):
    def setUp(self):
        super().setUp()
        self.handled = []
        curved, self.log = load_curved()
        self.protocol = curved.RADIUSAccess(dict=self.dict, hosts={
            '127.0.0.1': RemoteHost('127.0.0.1', SECRET, 'localhost')})
        self.protocol.processPacket = self.handled.append

    def handle(self, req):
        self.protocol.datagramReceived(req.RequestPacket(), ('127.0.0.1', 1812))

    def testValidMessageAuthenticator(self):
        self.handle(self.request())
        self.assertEqual(len(self.handled), 1)
        self.assertTrue(self.handled[0].verify_message_authenticator())

    def testInvalidMessageAuthenticator(self):
        req = self.request()
        req.RequestPacket()
        req.message_authenticator = False
        req['User-Name'] = 'mallory'
        self.handle(req)
        self.assertEqual(self.handled, [])
        self.assertIn('invalid Message-Authenticator', self.log.msg.call_args[0][0])

    def testMissingMessageAuthenticator(self):
        self.handle(self.request(message_authenticator=False))
        self.assertEqual(len(self.handled), 1)

        self.protocol.enforce_ma = True
        self.handle(self.request(message_authenticator=False))
        self.assertEqual(len(self.handled), 1)
        self.assertIn('without Message-Authenticator', self.log.msg.call_args[0][0])
