# server_async.py
#
# Copyright 2018-2019 Geaaru <geaaru@gmail.com>

import asyncio
import logging
import socket

from abc import abstractmethod, ABCMeta
from enum import Enum
from datetime import datetime, timezone
from pyrad.packet import Packet, AccessAccept, AccessReject, \
    AccountingRequest, AccountingResponse, \
    DisconnectACK, DisconnectNAK, DisconnectRequest, CoARequest, \
    CoAACK, CoANAK, AccessRequest, AuthPacket, AcctPacket, CoAPacket, \
    PacketError

from pyrad.server import ServerPacketError, CheckMessageAuthenticator, _LookupHost


def _endpoint_options():
    # reuse_port raises ValueError on platforms without SO_REUSEPORT,
    # e.g. Windows
    if hasattr(socket, 'SO_REUSEPORT'):
        return {'reuse_port': True}
    return {}


def _is_open(protocol):
    # the transport is set by connection_made and closed again by
    # create_datagram_endpoint if it fails or is cancelled afterwards
    return protocol.transport is not None and not protocol.transport.is_closing()


class ServerType(Enum):
    Auth = 'Authentication'
    Acct = 'Accounting'
    Coa = 'Coa'


class DatagramProtocolServer(asyncio.Protocol):
    """The transport of one listening socket of a :class:`ServerAsync`.

    :meth:`ServerAsync.initialize_transports` creates one for each address
    and port it listens on, and passes it to the packet handlers as
    ``protocol``. Don't create it yourself.

    :ivar ip: address the socket is bound to
    :vartype ip: str
    :ivar port: port the socket is bound to
    :vartype port: int
    """

    def __init__(self, ip, port, logger, server, server_type, hosts,
                 request_callback):
        self.transport = None
        self.ip = ip
        self.port = port
        self.logger = logger
        self.server = server
        self.hosts = hosts
        self.server_type = server_type
        self.request_callback = request_callback

    def connection_made(self, transport):
        self.transport = transport
        self.logger.info('[%s:%d] Transport created', self.ip, self.port)

    def connection_lost(self, exc):
        if exc:
            self.logger.warning('[%s:%d] Connection lost: %s', self.ip, self.port, str(exc))
        else:
            self.logger.info('[%s:%d] Transport closed', self.ip, self.port)

    def send_response(self, reply, addr):
        """Send a reply packet to a client.

        :param reply: reply packet, e.g. created with
            :meth:`ServerAsync.CreateReplyPacket`
        :type  reply: pyrad.packet.Packet
        :param  addr: address of the client, as passed to the handler
        :type   addr: tuple
        """
        self.transport.sendto(reply.ReplyPacket(), addr)

    def datagram_received(self, data, addr):
        self.logger.debug('[%s:%d] Received %d bytes from %s', self.ip, self.port, len(data), addr)

        receive_date = datetime.now(timezone.utc)

        remote_host = _LookupHost(self.hosts, addr[0])
        if remote_host is None and '0.0.0.0' in self.hosts:
            remote_host = self.hosts['0.0.0.0']
        if remote_host is None:
            self.logger.warning('[%s:%d] Drop packet from unknown source %s', self.ip, self.port, addr)
            return

        try:
            self.logger.debug('[%s:%d] Received from %s packet: %s', self.ip, self.port, addr, data.hex())
            req = Packet(packet=data, dict=self.server.dict)
        except Exception as exc:
            self.logger.error('[%s:%d] Error on decode packet: %s', self.ip, self.port, exc)
            return

        try:
            if req.code in (AccountingResponse, AccessAccept, AccessReject, CoANAK, CoAACK, DisconnectNAK, DisconnectACK):
                raise ServerPacketError('Invalid response packet %d' % req.code)

            elif self.server_type == ServerType.Auth:
                if req.code != AccessRequest:
                    raise ServerPacketError('Received non-auth packet on auth port')
                req = AuthPacket(secret=remote_host.secret,
                                 dict=self.server.dict,
                                 packet=data)
                CheckMessageAuthenticator(req, self.server.enforce_ma)

            elif self.server_type == ServerType.Coa:
                if req.code != DisconnectRequest and req.code != CoARequest:
                    raise ServerPacketError('Received non-coa packet on coa port')
                req = CoAPacket(secret=remote_host.secret,
                                dict=self.server.dict,
                                packet=data)
                if self.server.enable_pkt_verify:
                    if not req.VerifyCoARequest():
                        raise PacketError('Packet verification failed')

            elif self.server_type == ServerType.Acct:

                if req.code != AccountingRequest:
                    raise ServerPacketError('Received non-acct packet on acct port')
                req = AcctPacket(secret=remote_host.secret,
                                 dict=self.server.dict,
                                 packet=data)
                if self.server.enable_pkt_verify:
                    if not req.VerifyAcctRequest():
                        raise PacketError('Packet verification failed')

            # Call request callback
            self.request_callback(self, req, addr)
        except Exception as exc:
            if self.server.debug:
                self.logger.exception('[%s:%d] Error for packet from %s', self.ip, self.port, addr)
            else:
                self.logger.error('[%s:%d] Error for packet from %s: %s', self.ip, self.port, addr, exc)

        process_date = datetime.now(timezone.utc)
        self.logger.debug('[%s:%d] Request from %s processed in %d ms', self.ip, self.port, addr, (process_date-receive_date).microseconds/1000)

    def error_received(self, exc):
        self.logger.error('[%s:%d] Error received: %s', self.ip, self.port, exc)

    async def close_transport(self):
        if self.transport:
            self.logger.debug('[%s:%d] Close transport...', self.ip, self.port)
            self.transport.close()
            self.transport = None

    def __str__(self):
        return 'DatagramProtocolServer(ip=%s, port=%d)' % (self.ip, self.port)

    # Used as protocol_factory
    def __call__(self):
        return self


class ServerAsync(metaclass=ABCMeta):
    """Basic asyncio RADIUS server.

    Derive from this class and implement all four packet handlers,
    :meth:`handle_auth_packet`, :meth:`handle_acct_packet`,
    :meth:`handle_coa_packet` and :meth:`handle_disconnect_packet`;
    instantiating a class that lacks one of them raises a
    :exc:`TypeError`. Then create the server and await
    :meth:`initialize_transports` in the running event loop to start
    listening.

    The handlers are plain methods called for each received request, not
    coroutines: an ``async def`` handler is never run (Python warns that
    the coroutine was never awaited and the client times out). For
    asynchronous work, start a task from the handler and send the reply
    from that task.
    """

    def __init__(self, auth_port=1812, acct_port=1813,
                 coa_port=3799, hosts=None, dictionary=None,
                 loop=None, logger_name='pyrad',
                 enable_pkt_verify=True,
                 debug=False, enforce_ma=False):
        """
        :param auth_port: port to listen on for authentication packets
        :type  auth_port: int
        :param acct_port: port to listen on for accounting packets
        :type  acct_port: int
        :param coa_port: port to listen on for CoA and Disconnect packets
        :type  coa_port: int
        :param hosts: clients allowed to send requests, mapping their IP
            address to a :class:`~pyrad.server.RemoteHost` with the shared
            secret. The entry ``'0.0.0.0'`` is used for all other clients.
            IPv4 clients of a socket bound to ``'::'`` are looked up by
            their IPv4 address. Requests of other clients are dropped.
        :type  hosts: dict[str, pyrad.server.RemoteHost]
        :param dictionary: RADIUS dictionary used to decode the requests
        :type  dictionary: pyrad.dictionary.Dictionary
        :param loop: event loop, by default the loop running when it is
            used
        :type  loop: asyncio.AbstractEventLoop
        :param logger_name: name of the logger
        :type  logger_name: str
        :param enable_pkt_verify: drop Accounting, CoA and Disconnect requests
            with an invalid Request Authenticator
        :type  enable_pkt_verify: bool
        :param debug: log a traceback for packets that fail verification or
            in a handler, instead of a one-line message
        :type  debug: bool
        :param enforce_ma: drop Access-Requests without a Message-Authenticator
            (an invalid Message-Authenticator is always dropped)
        :type  enforce_ma: bool
        """

        # resolved when used, asyncio.get_event_loop() fails outside of a
        # running loop since Python 3.14
        self.loop = loop
        self.logger = logging.getLogger(logger_name)

        if hosts is None:
            self.hosts = {}
        else:
            self.hosts = hosts

        self.auth_port = auth_port
        self.auth_protocols = []

        self.acct_port = acct_port
        self.acct_protocols = []

        self.coa_port = coa_port
        self.coa_protocols = []

        self.dict = dictionary
        self.enable_pkt_verify = enable_pkt_verify

        self.debug = debug
        self.enforce_ma = enforce_ma

    def __request_handler__(self, protocol, req, addr):

        try:
            if protocol.server_type == ServerType.Acct:
                self.handle_acct_packet(protocol, req, addr)
            elif protocol.server_type == ServerType.Auth:
                self.handle_auth_packet(protocol, req, addr)
            elif protocol.server_type == ServerType.Coa and \
                    req.code == CoARequest:
                self.handle_coa_packet(protocol, req, addr)
            elif protocol.server_type == ServerType.Coa and \
                    req.code == DisconnectRequest:
                self.handle_disconnect_packet(protocol, req, addr)
            else:
                self.logger.error('[%s:%s] Unexpected request found', protocol.ip, protocol.port)
        except Exception as exc:
            if self.debug:
                self.logger.exception('[%s:%s] Unexpected error', protocol.ip, protocol.port)

            else:
                self.logger.error('[%s:%s] Unexpected error: %s', protocol.ip, protocol.port, exc)

    def __is_present_proto__(self, ip, port):
        if port == self.auth_port:
            for proto in self.auth_protocols:
                if proto.ip == ip:
                    return True
        elif port == self.acct_port:
            for proto in self.acct_protocols:
                if proto.ip == ip:
                    return True
        elif port == self.coa_port:
            for proto in self.coa_protocols:
                if proto.ip == ip:
                    return True
        return False

    # noinspection PyPep8Naming
    @staticmethod
    def CreateReplyPacket(pkt, **attributes):
        """Create a reply to a received request.

        The reply is an Access-Accept for an Access-Request, an
        Accounting-Response for an Accounting-Request and a CoA-ACK for a
        CoA-Request or Disconnect-Request; change ``reply.code`` for
        another reply, e.g. ``pyrad.packet.AccessReject`` or
        ``pyrad.packet.DisconnectACK``. The Proxy-State attributes of the
        request are copied and replies to Access-Requests get a
        Message-Authenticator. Send it with
        :meth:`DatagramProtocolServer.send_response`.

        :param pkt: received request
        :type  pkt: pyrad.packet.Packet
        :param attributes: attributes to add to the reply, as keyword
            arguments like for :class:`pyrad.packet.Packet`
        :return: reply packet
        :rtype:  pyrad.packet.Packet
        """
        reply = pkt.CreateReply(**attributes)
        return reply

    @property
    def loop(self):
        """The event loop, the running one if none was passed."""
        if self._loop is not None:
            return self._loop
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            # outside of a running loop, as before
            return asyncio.get_event_loop()

    @loop.setter
    def loop(self, loop):
        self._loop = loop

    async def initialize_transports(self, enable_acct=False,
                                    enable_auth=False, enable_coa=False,
                                    addresses=None):
        """Open the sockets and start listening.

        Opens a socket for each address and enabled port in the running
        event loop. At least one of the ports has to be enabled, otherwise
        an :exc:`Exception` is raised. Addresses which are already listened
        on for a port are skipped, so this method can be called again to
        add addresses, or to retry after a socket couldn't be opened (the
        error of the socket is raised).

        :param enable_acct: listen for accounting packets
        :type  enable_acct: bool
        :param enable_auth: listen for authentication packets
        :type  enable_auth: bool
        :param enable_coa: listen for CoA and Disconnect packets
        :type  enable_coa: bool
        :param addresses: IP addresses to listen on, by default
            ``['127.0.0.1']``
        :type  addresses: list[str]
        """

        if not enable_acct and not enable_auth and not enable_coa:
            raise Exception('No transports selected')
        if not addresses or len(addresses) == 0:
            addresses = ['127.0.0.1']

        # a protocol is registered right away, so that a concurrent call
        # doesn't open it twice, and unregistered again if its socket can't
        # be opened, so that a later call can retry
        connects = []
        # noinspection SpellCheckingInspection
        for addr in addresses:
            for enabled, port, server_type, protocols in (
                    (enable_acct, self.acct_port, ServerType.Acct, self.acct_protocols),
                    (enable_auth, self.auth_port, ServerType.Auth, self.auth_protocols),
                    (enable_coa, self.coa_port, ServerType.Coa, self.coa_protocols)):
                if not enabled or self.__is_present_proto__(addr, port):
                    continue
                protocol = DatagramProtocolServer(
                    addr,
                    port,
                    self.logger, self,
                    server_type,
                    self.hosts,
                    self.__request_handler__
                )
                protocols.append(protocol)
                connects.append((protocols, protocol, self.loop.create_datagram_endpoint(
                    protocol,
                    local_addr=(addr, port),
                    **_endpoint_options()
                )))

        try:
            # wait for all, also if one fails
            results = await asyncio.gather(
                *(connect for _, _, connect in connects),
                return_exceptions=True,
            )
        finally:
            for protocols, protocol, _ in connects:
                if not _is_open(protocol) and protocol in protocols:
                    protocols.remove(protocol)

        for result in results:
            if isinstance(result, BaseException):
                raise result

    # noinspection SpellCheckingInspection
    async def deinitialize_transports(self, deinit_coa=True, deinit_auth=True, deinit_acct=True):
        """Close the sockets opened by :meth:`initialize_transports`.

        :param deinit_coa:  close the CoA transports
        :type  deinit_coa:  bool
        :param deinit_auth: close the authentication transports
        :type  deinit_auth: bool
        :param deinit_acct: close the accounting transports
        :type  deinit_acct: bool
        """
        if deinit_coa:
            for proto in self.coa_protocols:
                await proto.close_transport()
                del proto

            self.coa_protocols = []

        if deinit_auth:
            for proto in self.auth_protocols:
                await proto.close_transport()
                del proto

            self.auth_protocols = []

        if deinit_acct:
            for proto in self.acct_protocols:
                await proto.close_transport()
                del proto

            self.acct_protocols = []

    @abstractmethod
    def handle_auth_packet(self, protocol, pkt, addr):
        """Handle an Access-Request.

        Called for each Access-Request from a known client (a client in
        ``hosts`` or, if present, the ``'0.0.0.0'`` entry). A
        Message-Authenticator in the request has been verified, and with
        ``enforce_ma`` requests without one have been dropped. The
        User-Password is not verified: decrypt it with
        :meth:`pkt.PwDecrypt <pyrad.packet.AuthPacket.PwDecrypt>` and check
        it yourself.

        This is a plain method, not a coroutine (see :class:`ServerAsync`).
        To answer, send a reply with
        ``protocol.send_response(self.CreateReplyPacket(pkt), addr)``. If
        the handler doesn't reply, the request is dropped. An exception
        raised by the handler is logged and the request is dropped.

        :param protocol: transport the request was received on
        :type  protocol: DatagramProtocolServer
        :param pkt: received request, with ``pkt.secret`` set to the secret
            of the client
        :type  pkt: pyrad.packet.AuthPacket
        :param addr: address of the client
        :type  addr: tuple
        """

    @abstractmethod
    def handle_acct_packet(self, protocol, pkt, addr):
        """Handle an Accounting-Request.

        Called for each Accounting-Request from a known client. With
        ``enable_pkt_verify`` its Request Authenticator has been verified.
        Reply as described for :meth:`handle_auth_packet`.

        :param protocol: transport the request was received on
        :type  protocol: DatagramProtocolServer
        :param pkt: received request, with ``pkt.secret`` set to the secret
            of the client
        :type  pkt: pyrad.packet.AcctPacket
        :param addr: address of the client
        :type  addr: tuple
        """

    @abstractmethod
    def handle_coa_packet(self, protocol, pkt, addr):
        """Handle a CoA-Request.

        Called for each CoA-Request from a known client. With
        ``enable_pkt_verify`` its Request Authenticator has been verified.
        Reply as described for :meth:`handle_auth_packet`.

        :param protocol: transport the request was received on
        :type  protocol: DatagramProtocolServer
        :param pkt: received request, with ``pkt.secret`` set to the secret
            of the client
        :type  pkt: pyrad.packet.CoAPacket
        :param addr: address of the client
        :type  addr: tuple
        """

    @abstractmethod
    def handle_disconnect_packet(self, protocol, pkt, addr):
        """Handle a Disconnect-Request.

        Called for each Disconnect-Request from a known client. With
        ``enable_pkt_verify`` its Request Authenticator has been verified.
        Reply as described for :meth:`handle_auth_packet`.
        :meth:`CreateReplyPacket` creates a CoA-ACK; set ``reply.code`` to
        ``pyrad.packet.DisconnectACK`` or ``pyrad.packet.DisconnectNAK``.

        :param protocol: transport the request was received on
        :type  protocol: DatagramProtocolServer
        :param pkt: received request, with ``pkt.secret`` set to the secret
            of the client
        :type  pkt: pyrad.packet.CoAPacket
        :param addr: address of the client
        :type  addr: tuple
        """
