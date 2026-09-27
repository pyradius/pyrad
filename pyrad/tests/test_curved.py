"""Tests of the Twisted integration, with the twisted modules stubbed out so
they run without Twisted installed."""
import importlib
import sys
import types
import unittest
from io import StringIO
from unittest import mock

from pyrad import packet
from pyrad.dictionary import Dictionary
from pyrad.server import RemoteHost

SECRET = b'secret'

DICTIONARY = '''
ATTRIBUTE User-Name     1  string
ATTRIBUTE User-Password 2  string
'''


def load_curved():
    """Import pyrad.curved against stub twisted modules.

    :return: the curved module and the stub twisted.python.log
    """
    twisted = types.ModuleType('twisted')
    internet = types.ModuleType('twisted.internet')
    protocol = types.ModuleType('twisted.internet.protocol')
    protocol.DatagramProtocol = type('DatagramProtocol', (), {})
    internet.protocol = protocol
    internet.reactor = mock.Mock()
    python = types.ModuleType('twisted.python')
    python.log = mock.Mock()
    twisted.internet = internet
    twisted.python = python
    stubs = {
        'twisted': twisted,
        'twisted.internet': internet,
        'twisted.internet.protocol': protocol,
        'twisted.internet.reactor': internet.reactor,
        'twisted.python': python,
        'twisted.python.log': python.log,
    }
    with mock.patch.dict(sys.modules, stubs):
        sys.modules.pop('pyrad.curved', None)
        curved = importlib.import_module('pyrad.curved')
    sys.modules.pop('pyrad.curved', None)
    return curved, python.log


class CurvedTests(unittest.TestCase):
    def setUp(self):
        self.curved, self.log = load_curved()
        self.dict = Dictionary(StringIO(DICTIONARY))
        self.hosts = {'127.0.0.1': RemoteHost('127.0.0.1', SECRET, 'localhost')}

    def receive(self, protocol, pkt, host='127.0.0.1'):
        protocol.datagramReceived(pkt.RequestPacket(), (host, 1812))

    def testConstruction(self):
        protocol = self.curved.RADIUS(hosts=self.hosts, dict=self.dict)
        self.assertIs(protocol.hosts, self.hosts)
        self.assertIs(protocol.dict, self.dict)
        self.assertIsNone(protocol.processPacket(None))
        self.assertRaises(NotImplementedError, protocol.createPacket)

    def testCreatePacket(self):
        for klass, create in ((self.curved.RADIUSAccess, 'CreateAuthPacket'),
                              (self.curved.RADIUSAccounting, 'CreateAcctPacket')):
            protocol = klass(hosts=self.hosts, dict=self.dict)
            with mock.patch.object(protocol, create) as create_packet:
                protocol.createPacket(secret=SECRET)
            create_packet.assert_called_once_with(secret=SECRET)

    def testAccessRequest(self):
        protocol = self.curved.RADIUSAccess(hosts=self.hosts, dict=self.dict)
        protocol.processPacket = mock.Mock(wraps=protocol.processPacket)
        self.receive(protocol, packet.AuthPacket(secret=SECRET, dict=self.dict))
        pkt = protocol.processPacket.call_args[0][0]
        self.assertEqual(pkt.code, packet.AccessRequest)
        self.assertEqual(pkt.source, ('127.0.0.1', 1812))
        self.log.msg.assert_not_called()

    def testAccountingRequest(self):
        protocol = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        self.receive(protocol, packet.AcctPacket(secret=SECRET, dict=self.dict))
        self.log.msg.assert_not_called()

    def testWrongPacketType(self):
        access = self.curved.RADIUSAccess(hosts=self.hosts, dict=self.dict)
        self.receive(access, packet.AcctPacket(secret=SECRET, dict=self.dict))
        accounting = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        self.receive(accounting, packet.AuthPacket(secret=SECRET, dict=self.dict))
        messages = [call[0][0] for call in self.log.msg.call_args_list]
        self.assertEqual(len(messages), 2)
        self.assertIn('non-AccessRequest packet', messages[0])
        self.assertIn('non-AccountingRequest packet', messages[1])

    def testInvalidPacket(self):
        protocol = self.curved.RADIUSAccess(hosts=self.hosts, dict=self.dict)
        protocol.datagramReceived(b'garbage', ('127.0.0.1', 1812))
        self.assertIn('Dropping invalid packet', self.log.msg.call_args[0][0])

    def testUnknownHost(self):
        protocol = self.curved.RADIUSAccess(hosts=self.hosts, dict=self.dict)
        protocol.processPacket = mock.Mock()
        self.receive(protocol, packet.AuthPacket(secret=SECRET, dict=self.dict),
                     host='192.0.2.1')
        protocol.processPacket.assert_not_called()
        self.assertIn('unknown host 192.0.2.1', self.log.msg.call_args[0][0])

    def received(self, protocol, pkt, host='127.0.0.1'):
        """Receive a packet and return what was passed to processPacket."""
        protocol.processPacket = mock.Mock()
        self.receive(protocol, pkt, host)
        if not protocol.processPacket.called:
            return None
        return protocol.processPacket.call_args[0][0]

    def testDefaultArguments(self):
        one = self.curved.RADIUSAccess()
        two = self.curved.RADIUSAccess()
        self.assertEqual(one.hosts, {})
        self.assertIsNot(one.hosts, two.hosts)
        self.assertIsInstance(one.dict, Dictionary)
        self.assertIsNot(one.dict, two.dict)

    def testCreatePacketReturnsPacket(self):
        access = self.curved.RADIUSAccess(hosts=self.hosts, dict=self.dict)
        self.assertIsInstance(access.createPacket(secret=SECRET), packet.AuthPacket)
        accounting = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        self.assertIsInstance(accounting.createPacket(secret=SECRET), packet.AcctPacket)

    def testAccessRequestIsDecodedWithSecret(self):
        protocol = self.curved.RADIUSAccess(hosts=self.hosts, dict=self.dict)
        req = packet.AuthPacket(secret=SECRET, dict=self.dict, User_Name='alice')
        req['User-Password'] = req.PwCrypt('password')
        pkt = self.received(protocol, req)
        self.assertIsInstance(pkt, packet.AuthPacket)
        self.assertEqual(pkt.secret, SECRET)
        self.assertEqual(pkt.PwDecrypt(pkt['User-Password'][0]), 'password')

    def testAccountingRequestIsDecodedWithSecret(self):
        protocol = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        pkt = self.received(protocol, packet.AcctPacket(secret=SECRET, dict=self.dict))
        self.assertIsInstance(pkt, packet.AcctPacket)
        self.assertEqual(pkt.secret, SECRET)
        self.assertEqual(pkt.CreateReply().secret, SECRET)

    def testInvalidAccountingRequest(self):
        protocol = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        self.assertIsNone(self.received(
            protocol, packet.AcctPacket(secret=b'wrong', dict=self.dict)))
        self.assertIn('verification failed', self.log.msg.call_args[0][0])

    def testAccountingVerificationDisabled(self):
        protocol = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict,
                                                enable_pkt_verify=False)
        self.assertIsNotNone(self.received(
            protocol, packet.AcctPacket(secret=b'wrong', dict=self.dict)))

    def testMappedAddress(self):
        protocol = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        pkt = self.received(protocol, packet.AcctPacket(secret=SECRET, dict=self.dict),
                            host='::ffff:127.0.0.1')
        self.assertEqual(pkt.secret, SECRET)
        self.assertEqual(pkt.source, ('::ffff:127.0.0.1', 1812))

    def testBaseClassUsesGenericPacket(self):
        # subclasses of RADIUS that don't implement createPacket keep
        # receiving generic packets
        protocol = self.curved.RADIUS(hosts=self.hosts, dict=self.dict)
        pkt = self.received(protocol, packet.AcctPacket(secret=SECRET, dict=self.dict))
        self.assertEqual(pkt.code, packet.AccountingRequest)
        self.assertEqual(pkt.secret, SECRET)
        self.assertIsNone(self.received(
            protocol, packet.AcctPacket(secret=b'wrong', dict=self.dict)))

    def testIPv6Source(self):
        self.hosts['::1'] = RemoteHost('::1', SECRET, 'localhost6')
        protocol = self.curved.RADIUSAccounting(hosts=self.hosts, dict=self.dict)
        protocol.processPacket = mock.Mock()
        req = packet.AcctPacket(secret=SECRET, dict=self.dict)
        protocol.datagramReceived(req.RequestPacket(), ('::1', 1813, 0, 0))
        self.assertEqual(protocol.processPacket.call_args[0][0].source, ('::1', 1813))
