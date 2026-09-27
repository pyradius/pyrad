"""Tests of the Twisted integration, with the twisted modules stubbed out so
they run without Twisted installed."""
import importlib
import sys
import types
import unittest
from unittest import mock

from pyrad import packet
from pyrad.dictionary import Dictionary

SECRET = b'secret'


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
        self.dict = Dictionary()
        self.hosts = {'127.0.0.1': object()}

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
