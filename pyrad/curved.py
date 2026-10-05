# curved.py
#
# Copyright 2002 Wichert Akkerman <wichert@wiggy.net>

"""Twisted integration code
"""

__docformat__ = 'epytext en'

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log
import sys
from pyrad import dictionary
from pyrad import host
from pyrad import packet
from pyrad.server import CheckMessageAuthenticator
from pyrad.server import ServerPacketError
from pyrad.server import _LookupHost


class PacketError(Exception):
    """Exception class for bogus packets

    PacketError exceptions are only used inside the Server class to
    abort processing of a packet.

    NOTE: this is not pyrad.packet.PacketError, which it shadows in this
    module; packet handlers may raise either.
    """


class RADIUS(host.Host, protocol.DatagramProtocol):
    def __init__(self, hosts=None, dict=None, enforce_ma=False,
                 enable_pkt_verify=True):
        """Constructor.

        @param hosts: hosts who we can talk to, packets from other hosts
            are dropped
        @type hosts: dictionary mapping IP to RemoteHost class instances
        @param dict: RADIUS dictionary to use
        @type dict: Dictionary class instance
        @param enforce_ma: drop Access-Requests without Message-Authenticator
            (an invalid Message-Authenticator is always dropped)
        @type enforce_ma: bool
        @param enable_pkt_verify: drop Accounting-Requests with an invalid
            request authenticator
        @type enable_pkt_verify: bool
        """
        if dict is None:
            dict = dictionary.Dictionary()
        host.Host.__init__(self, dict=dict)
        if hosts is None:
            hosts = {}
        self.hosts = hosts
        self.enforce_ma = enforce_ma
        self.enable_pkt_verify = enable_pkt_verify

    def processPacket(self, pkt):
        pass

    def createPacket(self, **kwargs):
        raise NotImplementedError('Attempted to use a pure base class')

    def _createPacket(self, **kwargs):
        if type(self).createPacket is RADIUS.createPacket:
            # createPacket is not implemented, use a generic packet
            return self.CreatePacket(**kwargs)
        return self.createPacket(**kwargs)

    def _verifyPacket(self, pkt):
        """Verify a received request the way pyrad.server.Server does.

        @raise ServerPacketError: if the packet should be dropped
        @raise packet.PacketError: if the packet should be dropped
        """
        if pkt.code == packet.AccessRequest:
            CheckMessageAuthenticator(pkt, self.enforce_ma)
        elif pkt.code == packet.AccountingRequest and self.enable_pkt_verify:
            if not packet.AcctPacket.VerifyAcctRequest(pkt):
                raise packet.PacketError('Packet verification failed')

    def datagramReceived(self, datagram, source):
        host, port = source[:2]
        try:
            pkt = self._createPacket(packet=datagram)
        except packet.PacketError as err:
            log.msg('Dropping invalid packet: ' + str(err))
            return
        except Exception as err:
            # not authenticated yet, log one line like Server._GrabPacket
            log.msg('Dropping invalid packet: %s: %s'
                    % (type(err).__name__, err))
            return

        remote_host = _LookupHost(self.hosts, host)
        if remote_host is None:
            log.msg('Dropping packet from unknown host ' + host)
            return

        pkt.secret = remote_host.secret
        pkt.source = (host, port)
        try:
            self._verifyPacket(pkt)
        except (ServerPacketError, packet.PacketError) as err:
            log.msg('Dropping packet from %s: %s' % (host, str(err)))
            return

        try:
            self.processPacket(pkt)
        except (PacketError, packet.PacketError, ServerPacketError) as err:
            log.msg('Dropping packet from %s: %s' % (host, str(err)))
        except Exception:
            # e.g. a ValueError from an attribute decoder or a handler bug
            log.err(None, 'Error processing packet from %s' % host)


class RADIUSAccess(RADIUS):
    def createPacket(self, **kwargs):
        return self.CreateAuthPacket(**kwargs)

    def processPacket(self, pkt):
        if pkt.code != packet.AccessRequest:
            raise PacketError(
                    'non-AccessRequest packet on authentication socket')


class RADIUSAccounting(RADIUS):
    def createPacket(self, **kwargs):
        return self.CreateAcctPacket(**kwargs)

    def processPacket(self, pkt):
        if pkt.code != packet.AccountingRequest:
            raise PacketError(
                    'non-AccountingRequest packet on accounting socket')


if __name__ == '__main__':
    log.startLogging(sys.stdout, 0)
    reactor.listenUDP(1812, RADIUSAccess())
    reactor.listenUDP(1813, RADIUSAccounting())
    reactor.run()
