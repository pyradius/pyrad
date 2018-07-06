# client_async.py
#
# Copyright 2018-2020 Geaaru <geaaru<@>gmail.com>

__docformat__ = "epytext en"

from datetime import datetime
import asyncio
import six
import logging
import random

from pyrad.packet import Packet, AuthPacket, AcctPacket, CoAPacket


class DatagramProtocolClient(asyncio.Protocol):

    def __init__(self, server, port, logger,
                 client, retries=3, timeout=30):
        self.transport = None
        self.port = port
        self.server = server
        self.logger = logger
        self.retries = retries
        self.timeout = timeout
        self.client = client

        # Map of pending requests
        self.pending_requests = {}

        # Use cryptographic-safe random generator as provided by the OS.
        random_generator = random.SystemRandom()
        self.packet_id = random_generator.randrange(0, 256)

        self.timeout_future = None

    async def __timeout_handler__(self):

        try:

            while True:

                req2delete = []
                now = datetime.now()
                next_weak_up = self.timeout
                # noinspection PyShadowingBuiltins
                for id, req in self.pending_requests.items():

                    secs = (req['send_date'] - now).seconds
                    if secs > self.timeout:
                        if req['retries'] == self.retries:
                            self.logger.debug('[%s:%d] For request %d execute all retries', self.server, self.port, id)
                            req['future'].set_exception(
                                TimeoutError('Timeout on Reply')
                            )
                            req2delete.append(id)
                        else:
                            # Send again packet
                            req['send_date'] = now
                            req['retries'] += 1
                            self.logger.debug('[%s:%d] For request %d execute retry %d', self.server, self.port, id, req['retries'])
                            self.transport.sendto(req['packet'].RequestPacket())
                    elif next_weak_up > secs:
                        next_weak_up = secs

                # noinspection PyShadowingBuiltins
                for id in req2delete:
                    # Remove request for map
                    del self.pending_requests[id]

                await asyncio.sleep(next_weak_up)

        except asyncio.CancelledError:
            pass

    def send_packet(self, packet, future):
        if packet.id in self.pending_requests:
            raise Exception('Packet with id %d already present' % packet.id)

        # Store packet on pending requests map
        self.pending_requests[packet.id] = {
            'packet': packet,
            'creation_date': datetime.now(),
            'retries': 0,
            'future': future,
            'send_date': datetime.now()
        }

        # In queue packet raw on socket buffer
        self.transport.sendto(packet.RequestPacket())

    def connection_made(self, transport):
        self.transport = transport
        socket = transport.get_extra_info('socket')
        self.logger.info(
            '[%s:%d] Transport created with binding in %s:%d',
                self.server, self.port,
                socket.getsockname()[0],
                socket.getsockname()[1]
        )

        pre_loop = asyncio.get_event_loop()
        asyncio.set_event_loop(loop=self.client.loop)
        # Start asynchronous timer handler
        self.timeout_future = asyncio.ensure_future(
            self.__timeout_handler__()
        )
        asyncio.set_event_loop(loop=pre_loop)

    def error_received(self, exc):
        self.logger.error('[%s:%d] Error received: %s', self.server, self.port, exc)

    def connection_lost(self, exc):
        if exc:
            self.logger.warn('[%s:%d] Connection lost: %s', self.server, self.port, str(exc))
        else:
            self.logger.info('[%s:%d] Transport closed', self.server, self.port)

    # noinspection PyUnusedLocal
    def datagram_received(self, data, addr):
        try:
            reply = Packet(packet=data, dict=self.client.dict)

            if reply and reply.id in self.pending_requests:
                req = self.pending_requests[reply.id]
                packet = req['packet']

                reply.dict = packet.dict
                reply.secret = packet.secret

                if packet.VerifyReply(reply, data):
                    req['future'].set_result(reply)
                    # Remove request for map
                    del self.pending_requests[reply.id]
                else:
                    self.logger.warn('[%s:%d] Ignore invalid reply for id %d. %s', self.server, self.port, reply.id)
            else:
                self.logger.warn('[%s:%d] Ignore invalid reply: %d', self.server, self.port, data)

        except Exception as exc:
            self.logger.error('[%s:%d] Error on decode packet: %s', self.server, self.port, exc)

    async def close_transport(self):
        if self.transport:
            self.logger.debug('[%s:%d] Closing transport...', self.server, self.port)
            self.transport.close()
            self.transport = None
        if self.timeout_future:
            self.timeout_future.cancel()
            await self.timeout_future
            self.timeout_future = None

    def create_id(self):
        self.packet_id = (self.packet_id + 1) % 256
        return self.packet_id

    def __str__(self):
        return 'DatagramProtocolClient(server?=%s, port=%d)' % (self.server, self.port)

    # Used as protocol_factory
    def __call__(self):
        return self


class ClientAsync:
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.

    :ivar retries: number of times to retry sending a RADIUS request
    :type retries: integer
    :ivar timeout: number of seconds to wait for an answer
    :type timeout: integer
    """
    # noinspection PyShadowingBuiltins
    def __init__(self, server, auth_port=1812, acct_port=1813,
                 coa_port=3799, secret=six.b(''), dict=None,
                 loop=None, retries=3, timeout=30,
                 logger_name='pyrad'):

        """Constructor.

        :param    server: hostname or IP address of RADIUS server
        :type     server: string
        :param auth_port: port to use for authentication packets
        :type  auth_port: integer
        :param acct_port: port to use for accounting packets
        :type  acct_port: integer
        :param  coa_port: port to use for CoA packets
        :type   coa_port: integer
        :param    secret: RADIUS secret
        :type     secret: string
        :param      dict: RADIUS dictionary
        :type       dict: pyrad.dictionary.Dictionary
        :param      loop: Python loop handler
        :type       loop:  asyncio event loop
        """
        if not loop:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop
        self.logger = logging.getLogger(logger_name)

        self.server = server
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self.dict = dict

        self.auth_port = auth_port
        self.protocol_auth = None

        self.acct_port = acct_port
        self.protocol_acct = None

        self.protocol_coa = None
        self.coa_port = coa_port

    async def initialize_transports(self, enable_acct=False,
                                    enable_auth=False, enable_coa=False,
                                    local_addr=None, local_auth_port=None,
                                    local_acct_port=None, local_coa_port=None):

        task_list = []

        if not enable_acct and not enable_auth and not enable_coa:
            raise Exception('No transports selected')

        if enable_acct and not self.protocol_acct:
            self.protocol_acct = DatagramProtocolClient(
                self.server,
                self.acct_port,
                self.logger, self,
                retries=self.retries,
                timeout=self.timeout
            )
            bind_addr = None
            if local_addr and local_acct_port:
                bind_addr = (local_addr, local_acct_port)

            acct_connect = self.loop.create_datagram_endpoint(
                self.protocol_acct,
                reuse_address=True, reuse_port=True,
                remote_addr=(self.server, self.acct_port),
                local_addr=bind_addr
            )
            task_list.append(acct_connect)

        if enable_auth and not self.protocol_auth:
            self.protocol_auth = DatagramProtocolClient(
                self.server,
                self.auth_port,
                self.logger, self,
                retries=self.retries,
                timeout=self.timeout
            )
            bind_addr = None
            if local_addr and local_auth_port:
                bind_addr = (local_addr, local_auth_port)

            auth_connect = self.loop.create_datagram_endpoint(
                self.protocol_auth,
                reuse_address=True, reuse_port=True,
                remote_addr=(self.server, self.auth_port),
                local_addr=bind_addr
            )
            task_list.append(auth_connect)

        if enable_coa and not self.protocol_coa:
            self.protocol_coa = DatagramProtocolClient(
                self.server,
                self.coa_port,
                self.logger, self,
                retries=self.retries,
                timeout=self.timeout
            )
            bind_addr = None
            if local_addr and local_coa_port:
                bind_addr = (local_addr, local_coa_port)

            coa_connect = self.loop.create_datagram_endpoint(
                self.protocol_coa,
                reuse_address=True, reuse_port=True,
                remote_addr=(self.server, self.coa_port),
                local_addr=bind_addr
            )
            task_list.append(coa_connect)

        await asyncio.ensure_future(
            asyncio.gather(
                *task_list,
                return_exceptions=False,
            ),
            loop=self.loop
        )

    # noinspection SpellCheckingInspection
    async def deinitialize_transports(self, deinit_coa=True,
                                      deinit_auth=True,
                                      deinit_acct=True):
        if self.protocol_coa and deinit_coa:
            await self.protocol_coa.close_transport()
            del self.protocol_coa
            self.protocol_coa = None
        if self.protocol_auth and deinit_auth:
            await self.protocol_auth.close_transport()
            del self.protocol_auth
            self.protocol_auth = None
        if self.protocol_acct and deinit_acct:
            await self.protocol_acct.close_transport()
            del self.protocol_acct
            self.protocol_acct = None

    # noinspection PyPep8Naming
    def CreateAuthPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        if not self.protocol_auth:
            raise Exception('Transport not initialized')

        return AuthPacket(dict=self.dict,
                          id=self.protocol_auth.create_id(),
                          secret=self.secret, **args)

    # noinspection PyPep8Naming
    def CreateAcctPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        if not self.protocol_acct:
            raise Exception('Transport not initialized')

        return AcctPacket(id=self.protocol_acct.create_id(),
                          dict=self.dict,
                          secret=self.secret, **args)

    # noinspection PyPep8Naming
    def CreateCoAPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """

        if not self.protocol_acct:
            raise Exception('Transport not initialized')

        return CoAPacket(id=self.protocol_coa.create_id(),
                         dict=self.dict,
                         secret=self.secret, **args)

    # noinspection PyPep8Naming
    # noinspection PyShadowingBuiltins
    def CreatePacket(self, id, **args):
        if not id:
            raise Exception('Missing mandatory packet id')

        return Packet(id=id, dict=self.dict,
                      secret=self.secret, **args)

    # noinspection PyPep8Naming
    def SendPacket(self, pkt):
        """Send a packet to a RADIUS server.

        :param pkt: the packet to send
        :type  pkt: pyrad.packet.Packet
        :return:    Future related with packet to send
        :rtype:     asyncio.Future
        """

        ans = asyncio.Future(loop=self.loop)

        if isinstance(pkt, AuthPacket):
            if not self.protocol_auth:
                raise Exception('Transport not initialized')

            self.protocol_auth.send_packet(pkt, ans)

        elif isinstance(pkt, AcctPacket):
            if not self.protocol_acct:
                raise Exception('Transport not initialized')

        elif isinstance(pkt, CoAPacket):
            if not self.protocol_coa:
                raise Exception('Transport not initialized')
        else:
            raise Exception('Unsupported packet')

        return ans
