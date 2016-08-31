# curved.py
#
# Copyright 2002 Wichert Akkerman <wichert@wiggy.net>

"""Twisted integration code
"""

__docformat__ = 'epytext en'

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet import defer
from twisted.python import log
import sys
from pyrad import dictionary
from pyrad import host
from pyrad import packet


class PacketError(Exception):
    """Exception class for bogus packets

    PacketError exceptions are only used inside the Server class to
    abort processing of a packet.
    """


class RADIUS(host.Host, protocol.DatagramProtocol):
    def __init__(self, hosts={}, dict=dictionary.Dictionary()):
        host.Host.__init__(self, dict=dict)
        self.hosts = hosts

    def processPacket(self, pkt):
        pass

    def createPacket(self, **kwargs):
        raise NotImplementedError('Attempted to use a pure base class')

    def createReplyPacket(self, pkt, **attributes):
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        :param pkt:   original packet
        :type pkt:    Packet instance
        """
        reply = pkt.CreateReply(**attributes)
        reply.source = pkt.source
        return reply

    def datagramReceived(self, datagram, (host, port)):
        if host not in self.hosts:
            log.msg('Dropping packet from unknown host ' + host)
            return

        try:
            pkt = self.createPacket(packet=datagram,
                                    secret=self.hosts[host].secret)
        except packet.PacketError as err:
            log.msg('Dropping invalid packet: ' + str(err))
            return

        pkt.source = (host, port)

        def errback(err, host):
            if err.check(PacketError):
                log.msg('Dropping packet from %s: %s' % (
                    host, err.getErrorMessage()))
            else:
                return err

        d = defer.maybeDeferred(self.processPacket, pkt)
        d.addErrback(errback, host)
        return d


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
                'non-AccountingRequest packet on authentication socket')


if __name__ == '__main__':
    log.startLogging(sys.stdout, 0)
    reactor.listenUDP(1812, RADIUSAccess())
    reactor.listenUDP(1813, RADIUSAccounting())
    reactor.run()
