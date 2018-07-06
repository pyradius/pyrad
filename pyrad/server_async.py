# server_async.py
#
# Copyright 2018-2019 Geaaru <geaaru@gmail.com>

import asyncio
import logging
import traceback

from abc import abstractmethod, ABCMeta
from enum import Enum
from datetime import datetime
from pyrad.packet import Packet, AccessAccept, AccessReject, \
    AccountingRequest, AccountingResponse, \
    DisconnectACK, DisconnectNAK, DisconnectRequest, CoARequest, \
    CoAACK, CoANAK, AccessRequest, AuthPacket, AcctPacket, CoAPacket, \
    PacketError

from pyrad.server import ServerPacketError


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
            self.logger.warn('[%s:%d] Connection lost: %s', self.ip, self.port, str(exc))
        else:
            self.logger.info('[%s:%d] Transport closed', self.ip, self.port)

    def send_response(self, reply, addr):
        self.transport.sendto(reply.ReplyPacket(), addr)

    def datagram_received(self, data, addr):
        self.logger.debug('[%s:%d] Received %d bytes from %s', self.ip, self.port, len(data), addr)

        receive_date = datetime.utcnow()

        if addr[0] in self.hosts:
            remote_host = self.hosts[addr[0]]
        elif '0.0.0.0' in self.hosts:
            remote_host = self.hosts['0.0.0.0'].secret
        else:
            self.logger.warn('[%s:%d] Drop package from unknown source %s', self.ip, self.port, addr)
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
                if self.server.enable_pkt_verify:
                    if req.VerifyAuthRequest():
                        raise PacketError('Packet verification failed')

            elif self.server_type == ServerType.Coa:
                if req.code != DisconnectRequest and req.code != CoARequest:
                    raise ServerPacketError('Received non-coa packet on coa port')
                req = CoAPacket(secret=remote_host.secret,
                                dict=self.server.dict,
                                packet=data)
                if self.server.enable_pkt_verify:
                    if req.VerifyCoARequest():
                        raise PacketError('Packet verification failed')

            elif self.server_type == ServerType.Acct:

                if req.code != AccountingRequest:
                    raise ServerPacketError('Received non-acct packet on acct port')
                req = AcctPacket(secret=remote_host.secret,
                                 dict=self.server.dict,
                                 packet=data)
                if self.server.enable_pkt_verify:
                    if req.VerifyAcctRequest():
                        raise PacketError('Packet verification failed')

            # Call request callback
            self.request_callback(self, req, addr)
        except Exception as exc:
            if self.server.debug:
                self.logger.exception('[%s:%d] Error for packet from %s', self.ip, self.port, addr)
            else:
                self.logger.error('[%s:%d] Error for packet from %s: %s', self.ip, self.port, addr, exc)

        process_date = datetime.utcnow()
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

    def __init__(self, auth_port=1812, acct_port=1813,
                 coa_port=3799, hosts=None, dictionary=None,
                 loop=None, logger_name='pyrad',
                 enable_pkt_verify=False,
                 debug=False):

        if not loop:
            self.loop = asyncio.get_event_loop()
        else:
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
        """
        reply = pkt.CreateReply(**attributes)
        return reply

    async def initialize_transports(self, enable_acct=False,
                                    enable_auth=False, enable_coa=False,
                                    addresses=None):

        task_list = []

        if not enable_acct and not enable_auth and not enable_coa:
            raise Exception('No transports selected')
        if not addresses or len(addresses) == 0:
            addresses = ['127.0.0.1']

        # noinspection SpellCheckingInspection
        for addr in addresses:

            if enable_acct and not self.__is_present_proto__(addr, self.acct_port):
                protocol_acct = DatagramProtocolServer(
                    addr,
                    self.acct_port,
                    self.logger, self,
                    ServerType.Acct,
                    self.hosts,
                    self.__request_handler__
                )

                bind_addr = (addr, self.acct_port)
                acct_connect = self.loop.create_datagram_endpoint(
                    protocol_acct,
                    reuse_address=True, reuse_port=True,
                    local_addr=bind_addr
                )
                self.acct_protocols.append(protocol_acct)
                task_list.append(acct_connect)

            if enable_auth and not self.__is_present_proto__(addr, self.auth_port):
                protocol_auth = DatagramProtocolServer(
                    addr,
                    self.auth_port,
                    self.logger, self,
                    ServerType.Auth,
                    self.hosts,
                    self.__request_handler__
                )
                bind_addr = (addr, self.auth_port)

                auth_connect = self.loop.create_datagram_endpoint(
                    protocol_auth,
                    reuse_address=True, reuse_port=True,
                    local_addr=bind_addr
                )
                self.auth_protocols.append(protocol_auth)
                task_list.append(auth_connect)

            if enable_coa and not self.__is_present_proto__(addr, self.coa_port):
                protocol_coa = DatagramProtocolServer(
                    addr,
                    self.coa_port,
                    self.logger, self,
                    ServerType.Coa,
                    self.hosts,
                    self.__request_handler__
                )
                bind_addr = (addr, self.coa_port)

                coa_connect = self.loop.create_datagram_endpoint(
                    protocol_coa,
                    reuse_address=True, reuse_port=True,
                    local_addr=bind_addr
                )
                self.coa_protocols.append(protocol_coa)
                task_list.append(coa_connect)

        await asyncio.ensure_future(
            asyncio.gather(
                *task_list,
                return_exceptions=False,
            ),
            loop=self.loop
        )

    # noinspection SpellCheckingInspection
    async def deinitialize_transports(self, deinit_coa=True, deinit_auth=True, deinit_acct=True):

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
        pass

    @abstractmethod
    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    @abstractmethod
    def handle_coa_packet(self, protocol, pkt, addr):
        pass

    @abstractmethod
    def handle_disconnect_packet(self, protocol, pkt, addr):
        pass
