# client_async.py
#
# Copyright 2018-2020 Geaaru <geaaru<@>gmail.com>
"""asyncio RADIUS client."""

__docformat__ = "restructuredtext en"

import asyncio
import logging
import random
import socket
import time

from pyrad.client import _EapMd5Identity, _EapMd5Response
from pyrad.packet import Packet, AuthPacket, AcctPacket, CoAPacket, _EnforceMA


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
        # cancelled by close_transport; the CancelledError ends the task
        while True:

            req2delete = []
            # monotonic, not affected by steps of the system clock
            now = time.monotonic()
            next_wake_up = self.timeout
            # noinspection PyShadowingBuiltins
            for id, req in self.pending_requests.items():

                if req['future'].done():
                    # cancelled by the caller
                    req2delete.append(id)
                    continue

                secs = now - req['send_date']
                if secs >= self.timeout:
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
                        try:
                            self.transport.sendto(req['raw'])
                        except Exception as exc:
                            # without the traceback, which references
                            # the frame of this long-running task
                            req['future'].set_exception(
                                exc.with_traceback(None))
                            req2delete.append(id)
                elif next_wake_up > self.timeout - secs:
                    # wake up when this request times out
                    next_wake_up = self.timeout - secs

            # noinspection PyShadowingBuiltins
            for id in req2delete:
                # Remove request from map
                self.pending_requests.pop(id, None)

            await asyncio.sleep(next_wake_up)

    def send_packet(self, packet, future):
        if packet.id in self.pending_requests:
            raise Exception('Packet with id %d already present' % packet.id)

        # encode first, so that a packet which can't be encoded isn't left
        # in the pending requests
        raw = packet.RequestPacket()

        # Store packet on pending requests map, the dates are
        # time.monotonic() values
        now = time.monotonic()
        self.pending_requests[packet.id] = {
            'packet': packet,
            'raw': raw,
            'creation_date': now,
            'retries': 0,
            'future': future,
            'send_date': now
        }
        future.add_done_callback(
            lambda fut, id=packet.id: self.__forget_request__(id, fut))

        # In queue packet raw on socket buffer
        self.transport.sendto(raw)

    def __forget_request__(self, id, future):
        # remove the request once its future is done, e.g. cancelled by the
        # caller, unless the id was reused already
        req = self.pending_requests.get(id)
        if req is not None and req['future'] is future:
            del self.pending_requests[id]

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        self.logger.info('[%s:%d] Transport created with binding in %s:%d',
                         self.server, self.port,
                         sock.getsockname()[0],
                         sock.getsockname()[1])

        # Start asynchronous timer handler
        self.timeout_future = self.client.loop.create_task(
            self.__timeout_handler__()
        )

    def error_received(self, exc):
        self.logger.error('[%s:%d] Error received: %s', self.server, self.port, exc)

    def connection_lost(self, exc):
        if exc:
            self.logger.warning('[%s:%d] Connection lost: %s', self.server, self.port, str(exc))
        else:
            self.logger.info('[%s:%d] Transport closed', self.server, self.port)

    # noinspection PyUnusedLocal
    def datagram_received(self, data, addr):
        try:
            reply = Packet(packet=data, dict=self.client.dict)

            if reply.code and reply.id in self.pending_requests:
                req = self.pending_requests[reply.id]
                packet = req['packet']

                reply.dict = packet.dict
                reply.secret = packet.secret
                # needed to decrypt salt encrypted attributes of the reply
                reply.request_authenticator = packet.authenticator

                if packet.VerifyReply(reply, data, enforce_ma=self.client.enforce_ma):
                    # Remove request from map
                    del self.pending_requests[reply.id]
                    if not req['future'].done():
                        req['future'].set_result(reply)
                else:
                    self.logger.warning('[%s:%d] Ignore invalid reply for id %d: %s', self.server, self.port, reply.id, data)
            else:
                self.logger.warning('[%s:%d] Ignore invalid reply: %s', self.server, self.port, data)

        except Exception as exc:
            self.logger.error('[%s:%d] Error on decode packet: %s', self.server, self.port, exc)

    async def close_transport(self):
        # fail the requests that are still waiting for a reply
        for req in list(self.pending_requests.values()):
            if not req['future'].done():
                req['future'].set_exception(
                    ConnectionAbortedError('Transport closed'))
        self.pending_requests.clear()
        if self.transport:
            self.logger.debug('[%s:%d] Closing transport...', self.server, self.port)
            self.transport.close()
            self.transport = None
        if self.timeout_future:
            self.timeout_future.cancel()
            # wait for the cancelled task to end; unlike awaiting it, this
            # doesn't raise its CancelledError, only a cancellation of the
            # caller
            await asyncio.wait([self.timeout_future])
            self.timeout_future = None

    def create_id(self):
        # the next id which isn't used by a pending request
        for _ in range(256):
            self.packet_id = (self.packet_id + 1) % 256
            if self.packet_id not in self.pending_requests:
                return self.packet_id
        raise Exception('No free packet id, 256 requests are pending')

    def __str__(self):
        return 'DatagramProtocolClient(server=%s, port=%d)' % (self.server, self.port)

    # Used as protocol_factory
    def __call__(self):
        return self


class ClientAsync:
    """Basic asyncio RADIUS client.

    Sends requests to one RADIUS server, retransmits them if no reply is
    received and verifies the replies. Await
    :meth:`initialize_transports` before creating and sending packets,
    and :meth:`deinitialize_transports` when done. There is one transport
    (socket) each for authentication, accounting and CoA packets.

    :ivar  server: hostname or IP address of the RADIUS server
    :type  server: str
    :ivar  secret: RADIUS secret shared with the server
    :type  secret: bytes
    :ivar retries: number of times a request is retransmitted, it is sent
                   at most ``retries + 1`` times
    :type retries: int
    :ivar timeout: number of seconds to wait for a reply after each send
    :type timeout: float
    :ivar enforce_ma: require a Message-Authenticator in replies to
                      Access-Request and Status-Server packets
    :type enforce_ma: bool
    """
    # noinspection PyShadowingBuiltins
    def __init__(self, server, auth_port=1812, acct_port=1813,
                 coa_port=3799, secret=b'', dict=None,
                 loop=None, retries=3, timeout=30,
                 logger_name='pyrad', enforce_ma=None):

        """
        :param    server: hostname or IP address of the RADIUS server
        :type     server: str
        :param auth_port: server port for authentication packets
        :type  auth_port: int
        :param acct_port: server port for accounting packets
        :type  acct_port: int
        :param  coa_port: server port for CoA and Disconnect packets
        :type   coa_port: int
        :param    secret: RADIUS secret
        :type     secret: bytes
        :param      dict: RADIUS dictionary
        :type       dict: pyrad.dictionary.Dictionary
        :param      loop: event loop, defaults to the running loop
        :type       loop: asyncio.AbstractEventLoop
        :param   retries: number of times a request is retransmitted, it is
                          sent at most ``retries + 1`` times
        :type    retries: int
        :param   timeout: number of seconds to wait for a reply after each
                          send
        :type    timeout: float
        :param logger_name: name of the logger
        :type  logger_name: str
        :param enforce_ma: require a Message-Authenticator in replies to
                           Access-Request and Status-Server packets (a
                           Message-Authenticator in a reply is always
                           verified). ``True`` is recommended. If it is
                           not passed, it is ``False`` and a
                           :exc:`FutureWarning` is issued once per
                           process: the default will change to ``True`` in
                           a future release.
        :type  enforce_ma: bool
        """
        # resolved when used, asyncio.get_event_loop() fails outside of a
        # running loop since Python 3.14
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
        self.enforce_ma = _EnforceMA(enforce_ma)

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
                                    local_addr=None, local_auth_port=None,
                                    local_acct_port=None, local_coa_port=None):
        """Open the sockets to the server.

        At least one transport has to be enabled. Packets can only be
        created and sent for enabled transports. Transports which are
        already open are left as they are.

        :param     enable_acct: open the accounting transport
        :type      enable_acct: bool
        :param     enable_auth: open the authentication transport
        :type      enable_auth: bool
        :param      enable_coa: open the CoA transport
        :type       enable_coa: bool
        :param      local_addr: local address to bind to, with the local
                                port of a transport or any free port
        :type       local_addr: str
        :param local_auth_port: local port of the authentication transport,
                                only used with ``local_addr``
        :type  local_auth_port: int
        :param local_acct_port: local port of the accounting transport,
                                only used with ``local_addr``
        :type  local_acct_port: int
        :param  local_coa_port: local port of the CoA transport, only used
                                with ``local_addr``
        :type   local_coa_port: int
        :raise Exception: no transport is enabled
        :raise OSError: a socket cannot be opened
        """

        if not enable_acct and not enable_auth and not enable_coa:
            raise Exception('No transports selected')

        # a protocol is registered right away, so that a concurrent call
        # doesn't open it twice, and unregistered again if its socket can't
        # be opened, so that a later call can retry
        connects = []
        for enabled, name, port, local_port in (
                (enable_acct, 'protocol_acct', self.acct_port, local_acct_port),
                (enable_auth, 'protocol_auth', self.auth_port, local_auth_port),
                (enable_coa, 'protocol_coa', self.coa_port, local_coa_port)):
            if not enabled or getattr(self, name):
                continue
            protocol = DatagramProtocolClient(
                self.server,
                port,
                self.logger, self,
                retries=self.retries,
                timeout=self.timeout
            )
            setattr(self, name, protocol)

            bind_addr = None
            if local_addr:
                # any free port without a local port
                bind_addr = (local_addr, local_port or 0)

            connects.append((name, protocol, self.loop.create_datagram_endpoint(
                protocol,
                remote_addr=(self.server, port),
                local_addr=bind_addr,
                **_endpoint_options()
            )))

        try:
            # wait for all, also if one fails
            results = await asyncio.gather(
                *(connect for _, _, connect in connects),
                return_exceptions=True,
            )
        finally:
            for name, protocol, _ in connects:
                if _is_open(protocol) or getattr(self, name) is not protocol:
                    continue
                setattr(self, name, None)
                if protocol.timeout_future:
                    protocol.timeout_future.cancel()
                    protocol.timeout_future = None

        for result in results:
            if isinstance(result, BaseException):
                raise result

    # noinspection SpellCheckingInspection
    async def deinitialize_transports(self, deinit_coa=True,
                                      deinit_auth=True,
                                      deinit_acct=True):
        """Close the sockets to the server.

        Requests still waiting for a reply on a closed transport fail with
        :class:`ConnectionAbortedError`.

        :param deinit_coa:  close the CoA transport
        :type  deinit_coa:  bool
        :param deinit_auth: close the authentication transport
        :type  deinit_auth: bool
        :param deinit_acct: close the accounting transport
        :type  deinit_acct: bool
        """
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
        """Create an authentication packet for the server of this client.

        The packet has the dictionary and secret of the client and an id
        that is not used by a pending request of the authentication
        transport. The keyword arguments are passed to
        :class:`pyrad.packet.AuthPacket`: packet arguments (``code``,
        ``authenticator``, ``message_authenticator``, ``packet``) and
        attributes to add, with ``-`` in the attribute names replaced by
        ``_``. The default code is Access-Request, use
        ``code=pyrad.packet.StatusServer`` for a Status-Server packet to
        the authentication port.

        A Message-Authenticator is added when the packet is encoded, as
        countermeasure against the BlastRADIUS attack (CVE-2024-3596);
        disable it with ``message_authenticator=False``.

        For PAP the password must be encrypted:
        ``pkt['User-Password'] = pkt.PwCrypt(password)``.

        With ``auth_type='eap-md5'``, :meth:`SendPacket` authenticates with
        EAP-MD5 instead; User-Password then holds the cleartext password.

        :return: a new packet
        :rtype:  pyrad.packet.AuthPacket
        :raise Exception: the authentication transport is not initialized,
                          or 256 requests are pending
        """
        if not self.protocol_auth:
            raise Exception('Transport not initialized')
        if 'packet' not in args:
            # a decoded packet has a Message-Authenticator if it contains one
            args.setdefault('message_authenticator', True)

        return AuthPacket(dict=self.dict,
                          id=self.protocol_auth.create_id(),
                          secret=self.secret, **args)

    # noinspection PyPep8Naming
    def CreateAcctPacket(self, **args):
        """Create an accounting packet for the server of this client.

        The packet has the dictionary and secret of the client and an id
        that is not used by a pending request of the accounting transport.
        The keyword arguments are passed to
        :class:`pyrad.packet.AcctPacket`: packet arguments (``code``,
        ``authenticator``, ``message_authenticator``, ``packet``) and
        attributes to add, with ``-`` in the attribute names replaced by
        ``_``. The default code is Accounting-Request;
        ``code=pyrad.packet.StatusServer`` creates a Status-Server packet
        to the accounting port.

        :return: a new packet
        :rtype:  pyrad.packet.AcctPacket
        :raise Exception: the accounting transport is not initialized, or
                          256 requests are pending
        """
        if not self.protocol_acct:
            raise Exception('Transport not initialized')

        return AcctPacket(id=self.protocol_acct.create_id(),
                          dict=self.dict,
                          secret=self.secret, **args)

    # noinspection PyPep8Naming
    def CreateCoAPacket(self, **args):
        """Create a CoA-Request or Disconnect-Request for this client's server.

        The packet has the dictionary and secret of the client and an id
        that is not used by a pending request of the CoA transport. The
        keyword arguments are passed to :class:`pyrad.packet.CoAPacket`:
        packet arguments (``code``, ``authenticator``,
        ``message_authenticator``, ``packet``) and attributes to add, with
        ``-`` in the attribute names replaced by ``_``. The default code
        is CoA-Request, pass ``code=pyrad.packet.DisconnectRequest`` for a
        Disconnect-Request.

        :return: a new packet
        :rtype:  pyrad.packet.CoAPacket
        :raise Exception: the CoA transport is not initialized, or 256
                          requests are pending
        """

        if not self.protocol_coa:
            raise Exception('Transport not initialized')

        return CoAPacket(id=self.protocol_coa.create_id(),
                         dict=self.dict,
                         secret=self.secret, **args)

    # noinspection PyPep8Naming
    # noinspection PyShadowingBuiltins
    def CreatePacket(self, id, **args):
        """Create a generic packet with the dictionary and secret of the client.

        A generic :class:`pyrad.packet.Packet` cannot be sent with
        :meth:`SendPacket`, use :meth:`CreateAuthPacket`,
        :meth:`CreateAcctPacket` or :meth:`CreateCoAPacket` instead.

        :param id: packet identifier
        :type  id: int
        :param args: further arguments of :class:`pyrad.packet.Packet`
                     and attributes to add
        :return: a new packet
        :rtype:  pyrad.packet.Packet
        :raise Exception: ``id`` is None
        """
        if id is None:
            raise Exception('Missing mandatory packet id')

        return Packet(id=id, dict=self.dict,
                      secret=self.secret, **args)

    # noinspection PyPep8Naming
    def SendPacket(self, pkt):
        """Send a request to the RADIUS server.

        This is not a coroutine: the request is sent right away and a
        future is returned, await it for the reply. An
        :class:`~pyrad.packet.AuthPacket` is sent with the authentication
        transport, an :class:`~pyrad.packet.AcctPacket` with the
        accounting transport and a :class:`~pyrad.packet.CoAPacket` with
        the CoA transport.

        If no valid reply is received within ``timeout`` seconds, the
        request is retransmitted (the same bytes as the first attempt), at
        most ``retries`` times. Invalid replies are ignored. Without a
        valid reply the future fails with the builtin :class:`TimeoutError`
        after ``(retries + 1) * timeout`` seconds (on Python 3.10 this is
        not :class:`asyncio.TimeoutError`). It fails with
        :class:`ConnectionAbortedError` if :meth:`deinitialize_transports`
        closes the transport first.

        With ``auth_type='eap-md5'`` the client authenticates with
        EAP-MD5 (RFC 3748, RFC 3579), like
        :meth:`pyrad.client.Client.SendPacket`: the EAP-Response/Identity
        carries the User-Name, and User-Password holds the cleartext
        password, which is used for the MD5 response but not sent. The
        Access-Challenge of the server is answered automatically and the
        future has the final reply.

        :param pkt: the request to send
        :type  pkt: pyrad.packet.Packet
        :return:    future with the reply packet; check ``reply.code``
        :rtype:     asyncio.Future
        :raise Exception: the transport is not initialized, the packet
                          class is not supported, or a request with the
                          same id is pending
        :raise ValueError: an attribute value cannot be encoded, or
                           ``auth_type='eap-md5'`` without User-Name or
                           User-Password
        """
        if isinstance(pkt, AuthPacket) and pkt.auth_type == 'eap-md5':
            return self._SendEapMd5Packet(pkt)

        ans = asyncio.Future(loop=self.loop)

        if isinstance(pkt, AuthPacket):
            if not self.protocol_auth:
                raise Exception('Transport not initialized')

            self.protocol_auth.send_packet(pkt, ans)

        elif isinstance(pkt, AcctPacket):
            if not self.protocol_acct:
                raise Exception('Transport not initialized')

            self.protocol_acct.send_packet(pkt, ans)

        elif isinstance(pkt, CoAPacket):
            if not self.protocol_coa:
                raise Exception('Transport not initialized')

            self.protocol_coa.send_packet(pkt, ans)

        else:
            raise Exception('Unsupported packet')

        return ans

    def _SendEapMd5Packet(self, pkt):
        """Authenticate with EAP-MD5, see :meth:`SendPacket`.

        The EAP-Response/Identity is sent right away, the answer to the
        Access-Challenge by a task.

        :return: future with the final reply
        :rtype:  asyncio.Future
        """
        if not self.protocol_auth:
            raise Exception('Transport not initialized')
        (password, user_password) = _EapMd5Identity(pkt)
        try:
            first = asyncio.Future(loop=self.loop)
            self.protocol_auth.send_packet(pkt, first)
        except BaseException:
            pkt[2] = user_password
            raise
        task = self.loop.create_task(self._AnswerEapMd5Challenge(pkt, first, password))

        def done(task):
            # also if the task is cancelled before it runs
            if not first.done():
                first.cancel()
            pkt[2] = user_password
        task.add_done_callback(done)
        return task

    async def _AnswerEapMd5Challenge(self, pkt, first, password):
        reply = await first
        if not _EapMd5Response(pkt, reply, password):
            return reply
        # RFC 2865 section 4.4: a new Identifier
        pkt.id = self.protocol_auth.create_id()
        ans = asyncio.Future(loop=self.loop)
        self.protocol_auth.send_packet(pkt, ans)
        return await ans
