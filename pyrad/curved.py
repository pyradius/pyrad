# curved.py
#
# Copyright 2002 Wichert Akkerman <wichert@wiggy.net>

"""Twisted integration code.

RADIUS servers built on Twisted: :class:`RADIUSAccess` for authentication
and :class:`RADIUSAccounting` for accounting requests, to be passed to
``reactor.listenUDP``. Twisted is not a dependency of pyrad and has to be
installed to use this module.
"""

__docformat__ = "restructuredtext en"

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log
import sys
from pyrad import dictionary
from pyrad import host
from pyrad import packet
from pyrad.server import CheckMessageAuthenticator
from pyrad.server import ServerPacketError
from pyrad.server import _HostAddresses


class PacketError(Exception):
    """A received packet is dropped.

    Raised by :meth:`RADIUSAccess.processPacket` and
    :meth:`RADIUSAccounting.processPacket` for packets of the wrong type. A
    :meth:`~RADIUS.processPacket` override may raise it to drop a packet:
    the drop is logged as one line instead of a traceback.

    This is not :class:`pyrad.packet.PacketError`, which it shadows in this
    module; packet handlers may raise either, or
    :class:`pyrad.server.ServerPacketError`.
    """


class RADIUS(host.Host, protocol.DatagramProtocol):
    """Base class of the Twisted RADIUS servers.

    Receives and decodes packets, checks that they come from a known host,
    verifies them and passes them to :meth:`processPacket`. Use
    :class:`RADIUSAccess` or :class:`RADIUSAccounting` and override
    :meth:`processPacket`.

    Before :meth:`processPacket` is called, ``pkt.secret`` is set to the
    secret of the host and ``pkt.source`` to its ``(host, port)``. The
    Message-Authenticator of an Access-Request has been verified (and with
    ``enforce_ma`` required), and with ``enable_pkt_verify`` the Request
    Authenticator of an Accounting-Request.
    """

    def __init__(self, hosts=None, dict=None, enforce_ma=False,
                 enable_pkt_verify=True):
        """
        :param hosts: hosts allowed to send packets, mapping their IP
            address to a :class:`pyrad.server.RemoteHost` or to the secret.
            IPv4 clients of a socket bound to ``'::'`` are looked up by
            their IPv4 address. Unlike :class:`pyrad.server.Server`, there
            is no ``'0.0.0.0'`` entry for all other hosts: packets from
            other hosts are dropped.
        :type  hosts: dict[str, pyrad.server.RemoteHost or bytes]
        :param dict: RADIUS dictionary used to decode the packets, by
            default an empty dictionary
        :type  dict: pyrad.dictionary.Dictionary
        :param enforce_ma: drop Access-Requests without a Message-Authenticator
            (an invalid Message-Authenticator is always dropped)
        :type  enforce_ma: bool
        :param enable_pkt_verify: drop Accounting-Requests with an invalid
            Request Authenticator
        :type  enable_pkt_verify: bool
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
        """Process a received packet.

        Override it and call the base method first, which raises
        :class:`PacketError` for packets of the wrong type in
        :class:`RADIUSAccess` and :class:`RADIUSAccounting`. To answer,
        create a reply with ``pkt.CreateReply()`` and send it with
        ``self.transport.write(reply.ReplyPacket(), pkt.source)``. If no
        reply is sent, the request is dropped. Raise :class:`PacketError`
        to drop the packet with a one-line log message; other exceptions
        are logged with a traceback.

        :param pkt: received packet
        :type  pkt: pyrad.packet.Packet
        """
        pass

    def createPacket(self, **kwargs):
        """Create the packet object for a received datagram.

        :class:`RADIUSAccess` creates a :class:`pyrad.packet.AuthPacket`
        and :class:`RADIUSAccounting` a :class:`pyrad.packet.AcctPacket`.
        The base method raises :exc:`NotImplementedError`; a class that
        doesn't override it receives generic :class:`pyrad.packet.Packet`
        objects.

        :param kwargs: arguments for the packet class, e.g. ``packet``
        :return: the packet
        :rtype: pyrad.packet.Packet
        """
        raise NotImplementedError('Attempted to use a pure base class')

    def _createPacket(self, **kwargs):
        if type(self).createPacket is RADIUS.createPacket:
            # createPacket is not implemented, use a generic packet
            return self.CreatePacket(**kwargs)
        pkt = self.createPacket(**kwargs)
        if pkt is None:
            # an override written for 2.5.4, which never called createPacket
            return self.CreatePacket(**kwargs)
        return pkt

    def _HostSecret(self, key):
        """Return the secret of a hosts entry.

        The entry is a RemoteHost or the secret itself. Returns None if it
        has none (e.g. hosts is a set).
        """
        try:
            entry = self.hosts[key]
        except (TypeError, KeyError):
            return None
        if isinstance(entry, bytes):
            return entry
        return getattr(entry, 'secret', None)

    def _verifyPacket(self, pkt):
        """Verify a received request the way pyrad.server.Server does.

        :raises pyrad.server.ServerPacketError: if the packet should be
            dropped
        :raises pyrad.packet.PacketError: if the packet should be dropped
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

        key = next((k for k in _HostAddresses(host) if k in self.hosts), None)
        if key is None:
            log.msg('Dropping packet from unknown host ' + host)
            return
        secret = self._HostSecret(key)
        if secret is None:
            log.msg('Dropping packet from %s: no secret in its hosts entry'
                    % host)
            return

        pkt.secret = secret
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
    """Twisted RADIUS authentication server.

    Override :meth:`processPacket` and call the base method first, which
    drops all packets except Access-Requests. The User-Password is not
    verified: decrypt it with
    :meth:`pkt.PwDecrypt <pyrad.packet.AuthPacket.PwDecrypt>`.
    """

    def createPacket(self, **kwargs):
        return self.CreateAuthPacket(**kwargs)

    def processPacket(self, pkt):
        if pkt.code != packet.AccessRequest:
            raise PacketError(
                    'non-AccessRequest packet on authentication socket')


class RADIUSAccounting(RADIUS):
    """Twisted RADIUS accounting server.

    Override :meth:`processPacket` and call the base method first, which
    drops all packets except Accounting-Requests.
    """

    def createPacket(self, **kwargs):
        return self.CreateAcctPacket(**kwargs)

    def processPacket(self, pkt):
        if pkt.code != packet.AccountingRequest:
            raise PacketError(
                    'non-AccountingRequest packet on accounting socket')


if __name__ == '__main__':
    # demo only: without hosts every packet is dropped as from an unknown
    # host
    log.startLogging(sys.stdout, 0)
    reactor.listenUDP(1812, RADIUSAccess())
    reactor.listenUDP(1813, RADIUSAccounting())
    reactor.run()
