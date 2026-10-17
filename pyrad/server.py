# server.py
#
# Copyright 2003-2004,2007,2016 Wichert Akkerman <wichert@wiggy.net>

import ipaddress
import select
import socket
from pyrad import host
from pyrad import packet
import logging


logger = logging.getLogger('pyrad')


class RemoteHost:
    """A RADIUS client or server and its shared secret.

    Used as the values of the ``hosts`` mapping of :class:`Server`,
    :class:`pyrad.server_async.ServerAsync` and :class:`pyrad.proxy.Proxy`.
    pyrad only uses ``secret``: the servers look up the client by the
    key of the ``hosts`` mapping (the IP address as the socket reports it),
    not by ``address``. The address, name and ports are stored for the
    application and are not used by pyrad.
    """

    def __init__(self, address, secret, name, authport=1812, acctport=1813, coaport=3799):
        """
        :param  address: IP address of the host (informational)
        :type   address: str
        :param   secret: RADIUS shared secret
        :type    secret: bytes
        :param     name: short name of the host (informational)
        :type      name: str
        :param authport: authentication port of the host (informational)
        :type  authport: int
        :param acctport: accounting port of the host (informational)
        :type  acctport: int
        :param  coaport: CoA port of the host (informational)
        :type   coaport: int
        """
        self.address = address
        self.secret = secret
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport
        self.name = name


class ServerPacketError(Exception):
    """A received packet is dropped.

    Raised by :class:`Server`, :class:`pyrad.server_async.ServerAsync` and
    :class:`pyrad.proxy.Proxy` for packets they don't accept: packets from
    an unknown client, packets of the wrong type for the port they were
    received on, and Access-Requests with an invalid or (with
    ``enforce_ma``) a missing Message-Authenticator.

    A packet handler may raise it to drop a request: the server then logs
    a single line with the message instead of a traceback.
    """


def CheckMessageAuthenticator(pkt, enforce_ma=False):
    """Check the Message-Authenticator of a received Access-Request.

    This is the BlastRADIUS countermeasure (CVE-2024-3596) of the servers.
    An invalid Message-Authenticator is always rejected, a missing one only
    with ``enforce_ma``.

    :param        pkt: received packet with the secret set
    :type         pkt: pyrad.packet.Packet
    :param enforce_ma: require a Message-Authenticator
    :type  enforce_ma: bool
    :raise ServerPacketError: if the packet should be dropped
    """
    if pkt.message_authenticator:
        if not pkt.verify_message_authenticator():
            raise ServerPacketError(
                'Received Access-Request with invalid Message-Authenticator')
    elif enforce_ma:
        raise ServerPacketError(
            'Received Access-Request without Message-Authenticator')


def _HostAddresses(address):
    """Return the keys under which a source address is looked up in hosts.

    These are the address as received and, for an IPv4-mapped IPv6 address
    (an IPv4 client of a dual stack socket bound to '::'), its IPv4 form.

    :param address: source address of a packet
    :type  address: str
    :return: addresses to look up, in order
    :rtype:  list[str]
    """
    addresses = [address]
    try:
        mapped = ipaddress.ip_address(address).ipv4_mapped
    except (ValueError, AttributeError, TypeError):
        mapped = None
    if mapped is not None:
        addresses.append(str(mapped))
    return addresses


def _LookupHost(hosts, address):
    """Return the hosts entry of a source address, or None.

    :param   hosts: hosts who are allowed to talk to us
    :type    hosts: dict[str, RemoteHost]
    :param address: source address of a packet
    :type  address: str
    """
    for key in _HostAddresses(address):
        if key in hosts:
            return hosts[key]
    return None


class Server(host.Host):
    """Basic blocking RADIUS server.

    The server receives and decodes requests, checks that they come from a
    known client and are valid, and passes them to the packet handlers.
    Derive from it and override :meth:`HandleAuthPacket`,
    :meth:`HandleAcctPacket`, :meth:`HandleCoaPacket` and
    :meth:`HandleDisconnectPacket`; the default handlers ignore the
    request. Then call :meth:`Run`.

    :ivar hosts: clients allowed to send requests, see the ``hosts``
        parameter
    :vartype hosts: dict[str, RemoteHost]
    :cvar MaxPacketSize: size of the receive buffer (RADIUS packets are at
        most 4096 octets)
    :vartype MaxPacketSize: int
    """
    MaxPacketSize = 8192

    def __init__(self, addresses=[], authport=1812, acctport=1813, coaport=3799,
                 hosts=None, dict=None, auth_enabled=True, acct_enabled=True, coa_enabled=False,
                 enforce_ma=False, enable_pkt_verify=True):
        """
        :param addresses: IP addresses or host names to listen on. The
            constructor binds them with :meth:`~pyrad.server.Server.BindToAddress`. Without
            addresses no packets are received unless :meth:`~pyrad.server.Server.BindToAddress`
            is called.
        :type  addresses: list[str]
        :param authport: port to listen on for authentication packets
        :type  authport: int
        :param acctport: port to listen on for accounting packets
        :type  acctport: int
        :param coaport: port to listen on for CoA and Disconnect packets
        :type  coaport: int
        :param hosts: clients allowed to send requests, mapping their IP
            address to a :class:`~pyrad.server.RemoteHost` with the shared secret. The
            entry ``'0.0.0.0'`` is used for all other clients. IPv4 clients
            of a socket bound to ``'::'`` are looked up by their IPv4
            address. Requests of other clients are dropped.
        :type  hosts: dict[str, pyrad.server.RemoteHost]
        :param dict: RADIUS dictionary used to decode the requests
        :type  dict: pyrad.dictionary.Dictionary
        :param auth_enabled: listen for authentication packets
        :type  auth_enabled: bool
        :param acct_enabled: listen for accounting packets
        :type  acct_enabled: bool
        :param coa_enabled: listen for CoA and Disconnect packets
        :type  coa_enabled: bool
        :param enforce_ma: drop Access-Requests without a Message-Authenticator
            (an invalid Message-Authenticator is always dropped)
        :type  enforce_ma: bool
        :param enable_pkt_verify: drop Accounting, CoA and Disconnect requests
            with an invalid Request Authenticator
        :type  enable_pkt_verify: bool
        """
        host.Host.__init__(self, authport, acctport, coaport, dict)
        if hosts is None:
            self.hosts = {}
        else:
            self.hosts = hosts

        self.auth_enabled = auth_enabled
        self.authfds = []
        self.acct_enabled = acct_enabled
        self.acctfds = []
        self.coa_enabled = coa_enabled
        self.coafds = []
        self.enforce_ma = enforce_ma
        self.enable_pkt_verify = enable_pkt_verify

        for addr in addresses:
            self.BindToAddress(addr)

    def _GetAddrInfo(self, addr):
        """Use getaddrinfo to look up all addresses of an address.

        Returns a set of (family, address) tuples, or an empty list if the
        address can't be resolved.

        :param addr: IP address or host name to look up
        :type  addr: str
        """
        results = set()
        try:
            tmp = socket.getaddrinfo(addr, 80)
        except socket.gaierror:
            return []

        for el in tmp:
            results.add((el[0], el[4][0]))

        return results

    def BindToAddress(self, addr):
        """Listen on an address.

        Opens a socket for each enabled port (authentication, accounting,
        CoA). ``'0.0.0.0'`` listens on all IPv4 addresses, ``'::'`` on all
        IPv6 addresses and, on a dual stack host, on all IPv4 addresses as
        well. A host name is resolved and every address it resolves to is
        bound; a name that can't be resolved is ignored silently. Call it
        before :meth:`Run`.

        :param addr: IP address or host name to listen on
        :type  addr: str
        """
        addrFamily = self._GetAddrInfo(addr)
        for (family, address) in addrFamily:
            if self.auth_enabled:
                authfd = socket.socket(family, socket.SOCK_DGRAM)
                authfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                authfd.bind((address, self.authport))
                self.authfds.append(authfd)

            if self.acct_enabled:
                acctfd = socket.socket(family, socket.SOCK_DGRAM)
                acctfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                acctfd.bind((address, self.acctport))
                self.acctfds.append(acctfd)

            if self.coa_enabled:
                coafd = socket.socket(family, socket.SOCK_DGRAM)
                coafd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                coafd.bind((address, self.coaport))
                self.coafds.append(coafd)

    def HandleAuthPacket(self, pkt):
        """Handle an Access-Request.

        Called by :meth:`Run` for each Access-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        A Message-Authenticator in the request has been verified, and with
        ``enforce_ma`` requests without one have been dropped. The
        User-Password is not verified: decrypt it with
        :meth:`pkt.PwDecrypt <pyrad.packet.AuthPacket.PwDecrypt>` and check
        it yourself.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.AuthPacket
        """

    def HandleAcctPacket(self, pkt):
        """Handle an Accounting-Request.

        Called by :meth:`Run` for each Accounting-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        With ``enable_pkt_verify`` its Request Authenticator has been
        verified.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.AcctPacket
        """

    def HandleCoaPacket(self, pkt):
        """Handle a CoA-Request.

        Called by :meth:`Run` for each CoA-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        With ``enable_pkt_verify`` its Request Authenticator has been
        verified.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.CoAPacket
        """

    def HandleDisconnectPacket(self, pkt):
        """Handle a Disconnect-Request.

        Called by :meth:`Run` for each Disconnect-Request from a known client: a
        client in ``hosts`` or, if present, the ``'0.0.0.0'`` entry.
        With ``enable_pkt_verify`` its Request Authenticator has been
        verified. :meth:`CreateReplyPacket` creates a Disconnect-ACK; set
        ``reply.code`` to ``pyrad.packet.DisconnectNAK`` to refuse it.

        To answer, create the reply with :meth:`CreateReplyPacket` and send
        it with ``self.SendReplyPacket(pkt.fd, reply)``
        (:meth:`pyrad.host.Host.SendReplyPacket`). If the handler doesn't
        reply, the request is dropped. An exception raised by the handler
        is logged with a traceback and the request is dropped; raise
        :class:`ServerPacketError` to drop it with a one-line log message.

        The packet has the attributes ``pkt.source`` (the client address
        as returned by :meth:`socket.socket.recvfrom`), ``pkt.fd`` (the
        socket it was received on) and ``pkt.secret`` (the secret of the
        client).

        The default implementation ignores the request.

        :param pkt: received request
        :type  pkt: pyrad.packet.CoAPacket
        """

    def _AddSecret(self, pkt):
        """Add the secret of the client to a received packet.

        Raises :class:`ServerPacketError` for unknown hosts.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        remote_host = _LookupHost(self.hosts, pkt.source[0])
        if remote_host is not None:
            pkt.secret = remote_host.secret
        elif '0.0.0.0' in self.hosts:
            pkt.secret = self.hosts['0.0.0.0'].secret
        else:
            raise ServerPacketError('Received packet from unknown host')

    def _HandleAuthPacket(self, pkt):
        """Process a packet received on the authentication port.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        self._AddSecret(pkt)
        if pkt.code != packet.AccessRequest:
            raise ServerPacketError(
                'Received non-authentication packet on authentication port')
        CheckMessageAuthenticator(pkt, self.enforce_ma)
        self.HandleAuthPacket(pkt)

    def _HandleAcctPacket(self, pkt):
        """Process a packet received on the accounting port.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        self._AddSecret(pkt)
        if pkt.code != packet.AccountingRequest:
            raise ServerPacketError(
                    'Received non-accounting packet on accounting port')
        if self.enable_pkt_verify and not pkt.VerifyAcctRequest():
            raise packet.PacketError('Packet verification failed')
        self.HandleAcctPacket(pkt)

    def _HandleCoaPacket(self, pkt):
        """Process a packet received on the CoA port.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: pyrad.packet.Packet
        """
        self._AddSecret(pkt)
        if pkt.code not in (packet.CoARequest, packet.DisconnectRequest):
            raise ServerPacketError('Received non-coa packet on coa port')
        if self.enable_pkt_verify and not pkt.VerifyCoARequest():
            raise packet.PacketError('Packet verification failed')
        if pkt.code == packet.CoARequest:
            self.HandleCoaPacket(pkt)
        else:
            self.HandleDisconnectPacket(pkt)

    def _GrabPacket(self, pktgen, fd):
        """Read a packet from a network connection.

        This method assumes there is data waiting to be read.

        :param fd: socket to read packet from
        :type  fd: socket.socket
        :return: RADIUS packet
        :rtype:  pyrad.packet.Packet
        """
        (data, source) = fd.recvfrom(self.MaxPacketSize)
        try:
            pkt = pktgen(data)
        except packet.PacketError:
            raise
        except Exception as err:
            # the packet is not authenticated yet, never let it stop the
            # main loop
            raise packet.PacketError('%s: %s' % (type(err).__name__, err))
        pkt.source = source
        pkt.fd = fd
        return pkt

    def _PrepareSockets(self):
        """Prepare all sockets to receive packets."""
        for fd in self.authfds + self.acctfds + self.coafds:
            self._fdmap[fd.fileno()] = fd
            self._poll.register(fd.fileno(), select.POLLIN | select.POLLPRI | select.POLLERR)
        if self.auth_enabled:
            self._realauthfds = list(map(lambda x: x.fileno(), self.authfds))
        if self.acct_enabled:
            self._realacctfds = list(map(lambda x: x.fileno(), self.acctfds))
        if self.coa_enabled:
            self._realcoafds = list(map(lambda x: x.fileno(), self.coafds))

    def CreateReplyPacket(self, pkt, **attributes):
        """Create a reply to a received request.

        The reply is an Access-Accept for an Access-Request, an
        Accounting-Response for an Accounting-Request, a CoA-ACK for a
        CoA-Request and a Disconnect-ACK for a Disconnect-Request; change
        ``reply.code`` for another reply, e.g. ``pyrad.packet.AccessReject``
        or ``pyrad.packet.CoANAK``. The Proxy-State attributes of
        the request are copied, replies to Access-Requests get a
        Message-Authenticator, and ``reply.source`` is set to the client
        address so the reply can be sent with
        :meth:`pyrad.host.Host.SendReplyPacket`.

        :param pkt: received request
        :type  pkt: pyrad.packet.Packet
        :param attributes: attributes to add to the reply, as keyword
            arguments like for :class:`pyrad.packet.Packet`
        :return: reply packet
        :rtype:  pyrad.packet.Packet
        """
        reply = pkt.CreateReply(**attributes)
        reply.source = pkt.source
        return reply

    def _ProcessInput(self, fd):
        """Process available data.

        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls _HandleAuthPacket(), _HandleAcctPacket() or
        _HandleCoaPacket() depending on which socket is being processed.

        :param fd: socket to read packet from
        :type  fd: socket.socket
        """
        if self.auth_enabled and fd.fileno() in self._realauthfds:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateAuthPacket(packet=data), fd)
            self._HandleAuthPacket(pkt)
        elif self.acct_enabled and fd.fileno() in self._realacctfds:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateAcctPacket(packet=data), fd)
            self._HandleAcctPacket(pkt)
        elif self.coa_enabled:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateCoAPacket(packet=data), fd)
            self._HandleCoaPacket(pkt)
        else:
            raise ServerPacketError('Received packet for unknown handler')

    def Run(self):
        """Run the server; this method never returns.

        Waits for packets on the sockets opened by :meth:`BindToAddress`
        and passes valid requests to the packet handlers. Invalid packets
        are dropped and logged, and so are packets for which a handler
        raises an exception, so that a malformed packet can't stop the
        server. Uses :func:`select.poll`, which is not available on Windows.
        """
        self._poll = select.poll()
        self._fdmap = {}
        self._PrepareSockets()

        while True:
            for (fd, event) in self._poll.poll():
                if event == select.POLLIN:
                    try:
                        fdo = self._fdmap[fd]
                        self._ProcessInput(fdo)
                    except ServerPacketError as err:
                        logger.info('Dropping packet: ' + str(err))
                    except packet.PacketError as err:
                        logger.info('Received a broken packet: ' + str(err))
                    except Exception:
                        logger.exception('Error processing packet')
                else:
                    logger.error('Unexpected event in server main loop')
