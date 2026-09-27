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


class ServerType(Enum):
    Auth = 'Authentication'
    Acct = 'Accounting'
    Coa = 'Coa'


class DatagramProtocolServer(asyncio.Protocol):

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
        """Send a reply packet.

        :param reply: reply packet
        :type  reply: pyrad.packet.Packet
        :param  addr: address of the client, as passed to the handler
        :type   addr: (host, port) tuple
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
    Derive from this class and implement the handle_auth_packet,
    handle_acct_packet, handle_coa_packet and handle_disconnect_packet
    methods, then call initialize_transports to start listening.
    """

    def __init__(self, auth_port=1812, acct_port=1813,
                 coa_port=3799, hosts=None, dictionary=None,
                 loop=None, logger_name='pyrad',
                 enable_pkt_verify=True,
                 debug=False, enforce_ma=False):
        """Constructor.

        :param  auth_port: port to listen on for authentication packets
        :type   auth_port: integer
        :param  acct_port: port to listen on for accounting packets
        :type   acct_port: integer
        :param   coa_port: port to listen on for CoA packets
        :type    coa_port: integer
        :param      hosts: hosts who we can talk to
        :type       hosts: dictionary mapping IP to RemoteHost class instances
        :param dictionary: RADIUS dictionary to use
        :type  dictionary: pyrad.dictionary.Dictionary
        :param       loop: Python loop handler
        :type        loop: asyncio event loop
        :param logger_name: name of the logger
        :type  logger_name: string
        :param enable_pkt_verify: drop accounting, CoA and Disconnect requests
                                  with an invalid request authenticator
                                  (default True)
        :type  enable_pkt_verify: bool
        :param      debug: log the traceback of errors
        :type       debug: bool
        :param enforce_ma: drop Access-Requests without Message-Authenticator
                           (default False, an invalid Message-Authenticator
                           is always dropped)
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
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        :param pkt:   original packet
        :type pkt:    Packet instance
        :param attributes: attributes to add to the reply
        :return:      reply packet
        :rtype:       Packet instance
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
        At least one transport has to be enabled.

        :param enable_acct: listen for accounting packets
        :type  enable_acct: bool
        :param enable_auth: listen for authentication packets
        :type  enable_auth: bool
        :param  enable_coa: listen for CoA and Disconnect packets
        :type   enable_coa: bool
        :param   addresses: IP addresses to listen on (default 127.0.0.1)
        :type    addresses: sequence of strings
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
                # connection_made sets the transport before
                # create_datagram_endpoint returns
                if protocol.transport is None and protocol in protocols:
                    protocols.remove(protocol)

        for result in results:
            if isinstance(result, BaseException):
                raise result

    # noinspection SpellCheckingInspection
    async def deinitialize_transports(self, deinit_coa=True, deinit_auth=True, deinit_acct=True):
        """Close the sockets.

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
        """Authentication packet handler.
        Called for each valid Access-Request. Send the reply with
        protocol.send_response(reply, addr).

        :param protocol: protocol the packet was received on
        :type  protocol: DatagramProtocolServer
        :param      pkt: packet to process
        :type       pkt: pyrad.packet.AuthPacket
        :param     addr: address of the client
        :type      addr: (host, port) tuple
        """

    @abstractmethod
    def handle_acct_packet(self, protocol, pkt, addr):
        """Accounting packet handler.
        Called for each valid Accounting-Request, see handle_auth_packet.
        """

    @abstractmethod
    def handle_coa_packet(self, protocol, pkt, addr):
        """CoA packet handler.
        Called for each valid CoA-Request, see handle_auth_packet.
        """

    @abstractmethod
    def handle_disconnect_packet(self, protocol, pkt, addr):
        """Disconnect packet handler.
        Called for each valid Disconnect-Request, see handle_auth_packet.
        """
