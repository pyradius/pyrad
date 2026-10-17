# proxy.py
#
# Copyright 2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS proxy as defined in RFC 2865

from pyrad.server import ServerPacketError
from pyrad.server import Server
from pyrad.server import _LookupHost
from pyrad import packet
import select
import socket

# codes of the RADIUS replies accepted on the proxy socket
_REPLY_CODES = (packet.AccessAccept, packet.AccessReject,
                packet.AccountingResponse, packet.AccessChallenge,
                packet.DisconnectACK, packet.DisconnectNAK,
                packet.CoAACK, packet.CoANAK)


class Proxy(Server):
    """Base class for RADIUS proxies.

    A :class:`~pyrad.server.Server` with an extra socket,
    ``self._proxyfd``, to forward requests to home servers and receive
    their replies. :meth:`~pyrad.server.Server.Run` creates the socket
    (IPv4 only, not bound to a fixed port) before it starts waiting for
    packets.

    To proxy requests, override the packet handlers of
    :class:`~pyrad.server.Server` to forward a request: create a request
    for the home server, remember it together with the client request,
    and send it with
    ``self._proxyfd.sendto(request.RequestPacket(), (address, port))``.
    Override :meth:`_HandleProxyPacket` to process the replies: call the
    base method first, find the request by ``pkt.id``, verify the reply
    with :meth:`request.VerifyReply(pkt) <pyrad.packet.Packet.VerifyReply>`
    (the proxy doesn't verify replies itself), and answer the client.

    Home servers have to be in ``hosts`` with their secret; replies from
    other hosts are dropped (the ``'0.0.0.0'`` entry isn't used for the
    proxy socket). Note that a ``hosts`` entry also allows that host to
    send requests to the server.
    """

    def _PrepareSockets(self):
        Server._PrepareSockets(self)
        self._proxyfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._fdmap[self._proxyfd.fileno()] = self._proxyfd
        self._poll.register(self._proxyfd.fileno(),
                            (select.POLLIN | select.POLLPRI | select.POLLERR))

    def _HandleProxyPacket(self, pkt):
        """Process a reply received on the proxy socket.

        The base method sets ``pkt.secret`` to the secret of the home
        server from ``hosts`` and raises
        :class:`~pyrad.server.ServerPacketError` for packets from unknown
        hosts and for packets which are not a reply (Access-Accept,
        Access-Reject, Access-Challenge, Accounting-Response, CoA-ACK,
        CoA-NAK, Disconnect-ACK or Disconnect-NAK). It doesn't verify the
        reply. Override it, call the base method first and then process
        the reply. To drop the packet raise
        :class:`~pyrad.server.ServerPacketError`: the main loop drops the
        packet and logs the reason.

        :param pkt: received reply, with ``pkt.source`` set to the address
            of the home server
        :type  pkt: pyrad.packet.Packet
        """
        remote_host = _LookupHost(self.hosts, pkt.source[0])
        if remote_host is None:
            raise ServerPacketError('Received packet from unknown host')
        pkt.secret = remote_host.secret

        if pkt.code not in _REPLY_CODES:
            raise ServerPacketError('Received non-response on proxy socket')

    def _ProcessInput(self, fd):
        """Process available data.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop
        will drop the packet and log the reason.

        This function calls _HandleProxyPacket for the proxy socket and
        the base method for the other sockets.

        :param fd: socket to read packet from
        :type  fd: socket.socket
        """
        if fd.fileno() == self._proxyfd.fileno():
            pkt = self._GrabPacket(
                lambda data, s=self: s.CreatePacket(packet=data), fd)
            self._HandleProxyPacket(pkt)
        else:
            Server._ProcessInput(self, fd)
