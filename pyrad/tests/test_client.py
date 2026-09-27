import hashlib
import select
import socket
import struct
import threading
import time
import types
import unittest
from io import StringIO
from unittest import mock
from .mock import MockPacket
from .mock import MockPoll
from .mock import MockSocket
from pyrad.client import Client
from pyrad.client import Timeout
from pyrad.packet import AuthPacket
from pyrad.packet import AccountingResponse
from pyrad.packet import AcctPacket
from pyrad.packet import AccessAccept
from pyrad.packet import AccessChallenge
from pyrad.packet import AccessRequest
from pyrad.packet import AccountingRequest
from pyrad.dictionary import Dictionary

BIND_IP = "127.0.0.1"
BIND_PORT = 53535

ACCT_DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE Acct-Status-Type      40 integer
ATTRIBUTE Acct-Delay-Time       41 integer
ATTRIBUTE Salted                200 string encrypt=2
VALUE     Acct-Status-Type      Start 1
'''

EAP_DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE State                 24 octets
ATTRIBUTE EAP-Message           79 octets
ATTRIBUTE Message-Authenticator 80 octets
'''


class ConstructionTests(unittest.TestCase):
    def setUp(self):
        self.server = object()

    def testSimpleConstruction(self):
        client = Client(self.server)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 1812)
        self.assertEqual(client.acctport, 1813)
        self.assertEqual(client.secret, b'')
        self.assertEqual(client.retries, 3)
        self.assertEqual(client.timeout, 5)
        self.assertTrue(client.dict is None)

    def testParameterOrder(self):
        marker = object()
        client = Client(self.server, 123, 456, 789, "secret", marker)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.coaport, 789)
        self.assertEqual(client.secret, "secret")
        self.assertTrue(client.dict is marker)

    def testNamedParameters(self):
        marker = object()
        client = Client(server=self.server, authport=123, acctport=456,
                        secret="secret", dict=marker)
        self.assertTrue(client.server is self.server)
        self.assertEqual(client.authport, 123)
        self.assertEqual(client.acctport, 456)
        self.assertEqual(client.secret, "secret")
        self.assertTrue(client.dict is marker)


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.server = object()
        self.client = Client(self.server)
        self.orgsocket = socket.socket
        socket.socket = MockSocket

    def tearDown(self):
        socket.socket = self.orgsocket

    def testReopen(self):
        self.client._SocketOpen()
        sock = self.client._socket
        self.client._SocketOpen()
        self.assertTrue(sock is self.client._socket)

    def testBind(self):
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.address, (BIND_IP, BIND_PORT))
        self.assertEqual(self.client._socket.options,
                         [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)])

    def testBindClosesSocket(self):
        s = MockSocket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client._socket = s
        self.client._poll = MockPoll()
        self.client.bind((BIND_IP, BIND_PORT))
        self.assertEqual(s.closed, True)

    def testSendPacket(self):
        def MockSend(self, pkt, port):
            self._mock_pkt = pkt
            self._mock_port = port

        _SendPacket = Client._SendPacket
        Client._SendPacket = MockSend

        self.client.SendPacket(AuthPacket())
        self.assertEqual(self.client._mock_port, self.client.authport)

        self.client.SendPacket(AcctPacket())
        self.assertEqual(self.client._mock_port, self.client.acctport)

        Client._SendPacket = _SendPacket

    def testNoRetries(self):
        self.client.retries = 0
        self.assertRaises(Timeout, self.client._SendPacket, None, None)

    def testSingleRetry(self):
        self.client.retries = 1
        self.client.timeout = 0
        packet = MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(self.client._socket.output,
                         [("request packet", (self.server, 432))])

    def testDoubleRetry(self):
        self.client.retries = 2
        self.client.timeout = 0
        packet = MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(self.client._socket.output,
                         [("request packet", (self.server, 432)),
                          ("request packet", (self.server, 432))])

    def testAuthDelay(self):
        self.client.retries = 2
        self.client.timeout = 1
        packet = MockPacket(AccessRequest)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertFalse("Acct-Delay-Time" in packet)

    def testSingleAccountDelay(self):
        self.client.retries = 2
        self.client.timeout = 1
        packet = MockPacket(AccountingRequest)
        packet.dict = Dictionary(StringIO(ACCT_DICTIONARY))
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [1])

    def testDoubleAccountDelay(self):
        self.client.retries = 3
        self.client.timeout = 1
        packet = MockPacket(AccountingRequest)
        packet.dict = Dictionary(StringIO(ACCT_DICTIONARY))
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertEqual(packet["Acct-Delay-Time"], [2])

    def testAccountDelayWithoutDictionary(self):
        self.client.retries = 2
        self.client.timeout = 0
        packet = MockPacket(AccountingRequest)
        packet.dict = None
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)
        self.assertFalse("Acct-Delay-Time" in packet)
        self.assertEqual(len(self.client._socket.output), 2)

    def testIgnorePacketError(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b'valid reply')
        packet = MockPacket(AccountingRequest, verify=True, error=True)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)

    def testValidReply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b'valid reply')
        self.client._poll = MockPoll()
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(AccountingRequest, verify=True)
        reply = self.client._SendPacket(packet, 432)
        self.assertTrue(reply is packet.reply)

    def testInvalidReply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b'invalid reply')
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(AccountingRequest, verify=False)
        self.assertRaises(Timeout, self.client._SendPacket, packet, 432)


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server = object()
        self.client = Client(self.server, secret=b'zeer geheim')

    def testCreateAuthPacket(self):
        packet = self.client.CreateAuthPacket(id=15)
        self.assertTrue(isinstance(packet, AuthPacket))
        self.assertTrue(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, b'zeer geheim')

    def testCreateAcctPacket(self):
        packet = self.client.CreateAcctPacket(id=15)
        self.assertTrue(isinstance(packet, AcctPacket))
        self.assertTrue(packet.dict is self.client.dict)
        self.assertEqual(packet.id, 15)
        self.assertEqual(packet.secret, b'zeer geheim')


class EapMd5Tests(unittest.TestCase):
    """The EAP-MD5 exchange in SendPacket, with _SendPacket faked."""

    challenge = b'0123456789abcdef'

    def setUp(self):
        self.client = Client(object(), secret=b'secret')
        self.sent = []
        self.replies = []

    def fakeSendPacket(self, pkt, port):
        self.sent.append((port, pkt[79][0], pkt.get(24)))
        return self.replies.pop(0)

    def reply(self, code, attributes={}):
        reply = AuthPacket(code=code, secret=b'secret')
        for (key, value) in attributes.items():
            reply[key] = value
        return reply

    def send(self, attributes):
        pkt = self.client.CreateAuthPacket(auth_type='eap-md5')
        for (key, value) in attributes.items():
            pkt[key] = value
        self.client._SendPacket = self.fakeSendPacket
        return self.client.SendPacket(pkt)

    def testIdentity(self):
        accept = self.reply(AccessAccept)
        self.replies = [accept]
        self.assertIs(self.send({1: [b'alice']}), accept)
        ((port, eap, state),) = self.sent
        self.assertEqual(port, self.client.authport)
        self.assertEqual(eap[0:1], b'\x02')  # EAP-Response
        self.assertEqual(eap[2:], struct.pack('!HB', 10, 1) + b'alice')
        self.assertIsNone(state)

    def testChallenge(self):
        eap_request = struct.pack('!BBHBB', 1, 7, 22, 4, 16) + self.challenge
        accept = self.reply(AccessAccept)
        self.replies = [self.reply(AccessChallenge, {79: [eap_request], 24: [b'state']}),
                        accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), accept)
        self.assertEqual(len(self.sent), 2)
        # the EAP-Identity carries the User-Password if present
        self.assertEqual(self.sent[0][1][4:], b'\x01password')
        (port, eap, state) = self.sent[1]
        digest = hashlib.md5(b'\x07' + b'password' + self.challenge).digest()
        self.assertEqual(eap, struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest)
        self.assertEqual(state, [b'state'])

    def testChallengeWithName(self):
        # the Name after the Value is not part of the MD5 challenge
        eap_request = struct.pack('!BBHBB', 1, 7, 28, 4, 16) + self.challenge + b'server'
        accept = self.reply(AccessAccept)
        self.replies = [self.reply(AccessChallenge, {79: [eap_request], 24: [b'state']}),
                        accept]
        self.assertIs(self.send({1: [b'alice'], 2: [b'password']}), accept)
        eap = self.sent[1][1]
        digest = hashlib.md5(b'\x07' + b'password' + self.challenge).digest()
        self.assertEqual(eap, struct.pack('!BBHBB', 2, 7, 22, 4, 16) + digest)

    def testChallengeNewIdAndAuthenticator(self):
        # RFC 2865 section 4.4: the answer to an Access-Challenge is a new
        # Access-Request with a new Identifier and Request Authenticator
        self.client.dict = Dictionary(StringIO(EAP_DICTIONARY))
        eap_request = struct.pack('!BBHBB', 1, 7, 22, 4, 16) + self.challenge
        self.replies = [self.reply(AccessChallenge, {79: [eap_request], 24: [b'state']}),
                        self.reply(AccessAccept)]
        requests = []

        def fakeSendPacket(pkt, port):
            requests.append(pkt.RequestPacket())
            return self.replies.pop(0)

        pkt = self.client.CreateAuthPacket(auth_type='eap-md5', User_Name='alice')
        self.client._SendPacket = fakeSendPacket
        self.client.SendPacket(pkt)
        (first, second) = requests
        self.assertNotEqual(first[1], second[1])
        self.assertNotEqual(first[4:20], second[4:20])
        self.assertEqual(second[1], pkt.id)
        self.assertEqual(second[4:20], pkt.authenticator)
        decoded = AuthPacket(secret=b'secret', dict=self.client.dict, packet=second)
        self.assertTrue(decoded.verify_message_authenticator())

    def testChallengeIgnoredForPap(self):
        challenge = self.reply(AccessChallenge)
        self.replies = [challenge]
        pkt = self.client.CreateAuthPacket()
        pkt[79] = [b'eap']
        self.client._SendPacket = self.fakeSendPacket
        self.assertIs(self.client.SendPacket(pkt), challenge)
        self.assertEqual(len(self.sent), 1)


class LoopbackTests(unittest.TestCase):
    """_SendPacket against a fake server on a loopback socket."""

    def setUp(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(('127.0.0.1', 0))
        self.server.settimeout(5)
        port = self.server.getsockname()[1]
        self.client = Client('127.0.0.1', authport=port, acctport=port,
                             coaport=port, secret=b'secret',
                             retries=1, timeout=0.2)

    def tearDown(self):
        self.client._CloseSocket()
        self.server.close()

    def testClockStepBackwards(self):
        # a step of the wall clock does not extend the timeout
        real_time = time.time
        calls = []

        def stepping_time():
            calls.append(None)
            return real_time() - (3 if len(calls) > 1 else 0)

        clock = types.SimpleNamespace(time=stepping_time, monotonic=time.monotonic)
        start = time.monotonic()
        with mock.patch('pyrad.client.time', clock):
            self.assertRaises(Timeout, self.client.SendPacket,
                              self.client.CreateAcctPacket())
        self.assertLess(time.monotonic() - start, 2)

    def testAccountDelayUndefined(self):
        # a retry does not fail if the dictionary has no Acct-Delay-Time
        self.client.dict = Dictionary(StringIO('ATTRIBUTE User-Name 1 string\n'))
        self.client.retries = 2
        self.client.timeout = 0.1
        pkt = self.client.CreateAcctPacket(User_Name='alice')
        self.assertRaises(Timeout, self.client.SendPacket, pkt)
        self.server.recv(4096)
        self.server.recv(4096)
        self.assertEqual(pkt.keys(), ['User-Name'])

    def testLateReplyToEarlierAttempt(self):
        # every retry changes Acct-Delay-Time and so the Request
        # Authenticator; a late reply to an earlier attempt is accepted
        self.client.dict = Dictionary(StringIO(ACCT_DICTIONARY))
        self.client.retries = 2
        self.client.timeout = 0.5
        received = []

        def serve():
            received.append(self.server.recvfrom(4096))
            received.append(self.server.recvfrom(4096))
            (data, source) = received[0]
            request = AcctPacket(secret=b'secret', dict=self.client.dict, packet=data)
            reply = request.CreateReply()
            reply['Salted'] = 'salt'
            self.server.sendto(reply.ReplyPacket(), source)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            pkt = self.client.CreateAcctPacket(User_Name='alice', Acct_Status_Type='Start')
            reply = self.client.SendPacket(pkt)
        finally:
            thread.join()
        first = received[0][0]
        self.assertNotEqual(first[4:20], received[1][0][4:20])
        self.assertEqual(reply.code, AccountingResponse)
        self.assertEqual(reply.request_authenticator, first[4:20])
        self.assertEqual(reply['Salted'], ['salt'])
