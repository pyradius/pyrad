"""Tests of the client and server, running against each other on the
loopback interface."""
import select
import socket
import threading
import unittest
from io import StringIO

from pyrad import packet
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.server import RemoteHost, Server

SECRET = b'secret'
LOCALHOST = '127.0.0.1'

DICTIONARY = '''
ATTRIBUTE User-Name             1  string
ATTRIBUTE User-Password         2  string
ATTRIBUTE Reply-Message         18 string
ATTRIBUTE Acct-Status-Type      40 integer
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


class RadiusServer(Server):
    def HandleAuthPacket(self, pkt):
        reply = self.CreateReplyPacket(pkt, Reply_Message='hello')
        reply.code = packet.AccessAccept
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        self.SendReplyPacket(pkt.fd, self.CreateReplyPacket(pkt))

    def HandleCoaPacket(self, pkt):
        self.SendReplyPacket(pkt.fd, self.CreateReplyPacket(pkt))

    def HandleDisconnectPacket(self, pkt):
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.DisconnectACK
        self.SendReplyPacket(pkt.fd, reply)


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.dict = Dictionary(StringIO(DICTIONARY))
        (authport, acctport, coaport) = free_ports(3)
        self.server = RadiusServer(
            addresses=[LOCALHOST], authport=authport, acctport=acctport,
            coaport=coaport, coa_enabled=True, dict=self.dict,
            hosts={LOCALHOST: RemoteHost(LOCALHOST, SECRET, 'localhost')})
        self.server._poll = select.poll()
        self.server._fdmap = {}
        self.server._PrepareSockets()
        self.client = Client(server=LOCALHOST, authport=authport, acctport=acctport,
                             coaport=coaport, secret=SECRET, dict=self.dict,
                             retries=1, timeout=2, enforce_ma=True)

    def tearDown(self):
        for fd in self.server.authfds + self.server.acctfds + self.server.coafds:
            fd.close()

    def send(self, pkt, fds):
        """Send the packet while the server processes one packet."""
        def serve():
            (readable, _, _) = select.select(fds, [], [], 5)
            for fd in readable:
                self.server._ProcessInput(fd)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            return self.client.SendPacket(pkt)
        finally:
            thread.join()

    def testAuth(self):
        req = self.client.CreateAuthPacket(User_Name='alice')
        req['User-Password'] = req.PwCrypt('password')
        reply = self.send(req, self.server.authfds)
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply['Reply-Message'], ['hello'])
        self.assertEqual(reply.request_authenticator, req.authenticator)

    def testAcct(self):
        req = self.client.CreateAcctPacket(User_Name='alice', Acct_Status_Type='Start')
        self.assertEqual(self.send(req, self.server.acctfds).code, packet.AccountingResponse)

    def testCoA(self):
        req = self.client.CreateCoAPacket(User_Name='alice')
        self.assertEqual(self.send(req, self.server.coafds).code, packet.CoAACK)

    def testDisconnect(self):
        req = self.client.CreateCoAPacket(code=packet.DisconnectRequest, User_Name='alice')
        self.assertEqual(self.send(req, self.server.coafds).code, packet.DisconnectACK)

    def testInvalidReply(self):
        # a corrupt reply is ignored and the client times out
        self.client.timeout = 0.5
        (fd,) = self.server.authfds

        def reply():
            (data, source) = fd.recvfrom(4096)
            fd.sendto(b'\x02' + data[1:2] + b'\x00\x05x', source)
        thread = threading.Thread(target=reply)
        thread.start()
        try:
            self.assertRaises(Timeout, self.client.SendPacket,
                              self.client.CreateAuthPacket(User_Name='alice'))
        finally:
            thread.join()
