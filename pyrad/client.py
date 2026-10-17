# client.py
#
# Copyright 2002-2007 Wichert Akkerman <wichert@wiggy.net>
"""Blocking RADIUS client."""

__docformat__ = "restructuredtext en"

import hashlib
import select
import socket
import time
import struct
from pyrad import host
from pyrad import packet

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_TYPE_IDENTITY = 1
EAP_TYPE_MD5 = 4


def _EapMd5Identity(pkt):
    """Start an EAP-MD5 authentication (RFC 3748 section 5.4, RFC 3579):
    set the EAP-Response/Identity, which carries the User-Name, and remove
    the User-Password, which holds the cleartext password. RFC 3579
    section 3.3 doesn't allow User-Password together with EAP-Message.

    :param pkt: Access-Request with User-Name and User-Password
    :type  pkt: pyrad.packet.AuthPacket
    :return: the password and the removed User-Password values, to restore
             them with ``pkt[2] = values`` afterwards
    :rtype:  tuple
    :raise ValueError: User-Name or User-Password is missing
    """
    if 1 not in pkt or 2 not in pkt:
        raise ValueError('EAP-MD5 requires User-Name and the cleartext '
                         'password as User-Password')
    identity = pkt[1][0]
    user_password = pkt[2]
    del pkt[2]
    pkt[79] = [struct.pack('!BBHB', EAP_CODE_RESPONSE, packet.CurrentID,
                           len(identity) + 5, EAP_TYPE_IDENTITY) + identity]
    return (user_password[0], user_password)


def _EapMd5Response(pkt, reply, password):
    """Answer the EAP-MD5 challenge of an Access-Challenge.

    Sets the EAP-Response/MD5-Challenge, the State of the challenge and a
    new Request Authenticator in pkt (RFC 2865 section 4.4); the caller
    has to give it a new Identifier before sending it.

    :param pkt: the Access-Request the challenge replies to
    :type  pkt: pyrad.packet.AuthPacket
    :param reply: the reply to pkt
    :type  reply: pyrad.packet.Packet
    :param password: cleartext password
    :type  password: bytes
    :return: True if pkt now answers the challenge, False if the reply
             is not an EAP-MD5 challenge
    :rtype:  bool
    """
    if reply.code != packet.AccessChallenge:
        return False
    # RFC 3579 section 3.1: an EAP packet may be split over several
    # EAP-Message attributes
    eap = b''.join(reply.get(79, []))
    if len(eap) < 6 or eap[0] != EAP_CODE_REQUEST or eap[4] != EAP_TYPE_MD5:
        # not an EAP-MD5 challenge
        return False
    eap_id = eap[1]
    eap = eap[:struct.unpack('!H', eap[2:4])[0]]
    # RFC 3748 section 5.4: Type-Data is Value-Size, Value and an optional
    # Name; the response is the MD5 hash of the EAP Identifier, the
    # password and the Value (RFC 1994 section 4.1)
    value = eap[6:6 + eap[5]]
    digest = hashlib.md5(struct.pack('!B', eap_id) + password + value).digest()
    pkt[79] = [struct.pack('!BBHBB', EAP_CODE_RESPONSE, eap_id,
                           len(digest) + 6, EAP_TYPE_MD5, len(digest)) + digest]
    # RFC 2865 section 4.4: the State of the challenge is returned
    if 24 in reply:
        pkt[24] = reply[24]
    elif 24 in pkt:
        del pkt[24]
    # RFC 2865 section 3: the Request Authenticator is unique. The
    # Message-Authenticator is calculated with it when pkt is encoded.
    pkt.authenticator = pkt.CreateAuthenticator()
    return True


class Timeout(Exception):
    """Raised by :meth:`Client.SendPacket` when no valid reply was received.

    :class:`pyrad.client_async.ClientAsync` fails its futures with
    :class:`TimeoutError` instead.
    """


class Client(host.Host):
    """Basic blocking RADIUS client.

    Sends requests to one RADIUS server, retransmits them if no reply is
    received and verifies the replies. Packets are created with
    :meth:`CreateAuthPacket`, :meth:`CreateAcctPacket` and
    :meth:`CreateCoAPacket` and sent with :meth:`SendPacket`.

    :ivar  server: hostname or IP address of the RADIUS server
    :type  server: str
    :ivar  secret: RADIUS secret shared with the server
    :type  secret: bytes
    :ivar retries: maximum number of times a request is sent in total
                   (``0`` never sends it and raises :exc:`Timeout`)
    :type retries: int
    :ivar timeout: number of seconds to wait for a reply after each send
    :type timeout: float
    :ivar enforce_ma: require a Message-Authenticator in replies to
                      Access-Request and Status-Server packets
    :type enforce_ma: bool
    """
    def __init__(self, server, authport=1812, acctport=1813,
                 coaport=3799, secret=b'', dict=None, retries=3, timeout=5, enforce_ma=False):
        """
        :param   server: hostname or IP address of the RADIUS server
        :type    server: str
        :param authport: server port for authentication packets
        :type  authport: int
        :param acctport: server port for accounting packets
        :type  acctport: int
        :param  coaport: server port for CoA and Disconnect packets
        :type   coaport: int
        :param   secret: RADIUS secret
        :type    secret: bytes
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        :param  retries: maximum number of times a request is sent in total
        :type   retries: int
        :param  timeout: number of seconds to wait for a reply after each
                         send
        :type   timeout: float
        :param enforce_ma: require a Message-Authenticator in replies to
                           Access-Request and Status-Server packets (a
                           Message-Authenticator in a reply is always
                           verified)
        :type  enforce_ma: bool
        """
        host.Host.__init__(self, authport, acctport, coaport, dict)

        self.server = server
        self.secret = secret
        self._socket = None
        self.retries = retries
        self.timeout = timeout
        self.enforce_ma = enforce_ma
        self._poll = select.poll()

    def bind(self, addr):
        """Bind the client socket to a local address.

        Useful on a machine with multiple addresses. The socket is closed
        and opened again first.

        :param addr: local address (hostname or IP) and port to bind to,
                     port 0 for any free port
        :type  addr: tuple
        """
        self._CloseSocket()
        self._SocketOpen()
        self._socket.bind(addr)

    def _SocketOpen(self):
        try:
            family = socket.getaddrinfo(self.server, 80)[0][0]
        except Exception:
            family = socket.AF_INET
        if not self._socket:
            self._socket = socket.socket(family,
                                         socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_REUSEADDR, 1)
            self._poll.register(self._socket, select.POLLIN)

    def _CloseSocket(self):
        if self._socket:
            self._poll.unregister(self._socket)
            self._socket.close()
            self._socket = None

    def CreateAuthPacket(self, **args):
        """Create an authentication packet for the server of this client.

        The packet has the dictionary and secret of the client. The
        keyword arguments are passed to :class:`pyrad.packet.AuthPacket`:
        packet arguments (``code``, ``id``, ``authenticator``,
        ``auth_type``, ``message_authenticator``, ``packet``) and
        attributes to add, with ``-`` in the attribute names replaced by
        ``_``. The default code is Access-Request, use
        ``code=pyrad.packet.StatusServer`` for a Status-Server packet to
        the authentication port.

        A Message-Authenticator is added when the packet is encoded, as
        countermeasure against the BlastRADIUS attack (CVE-2024-3596);
        disable it with ``message_authenticator=False``.

        For PAP the password must be encrypted:
        ``pkt['User-Password'] = pkt.PwCrypt(password)``. For EAP-MD5 pass
        ``auth_type='eap-md5'`` and set the cleartext password as
        User-Password, see :meth:`SendPacket`.

        :return: a new packet
        :rtype:  pyrad.packet.AuthPacket
        """
        if 'packet' not in args:
            # a decoded packet has a Message-Authenticator if it contains one
            args.setdefault('message_authenticator', True)
        return host.Host.CreateAuthPacket(self, secret=self.secret, **args)

    def CreateAcctPacket(self, **args):
        """Create an accounting packet for the server of this client.

        The packet has the dictionary and secret of the client. The
        keyword arguments are passed to :class:`pyrad.packet.AcctPacket`:
        packet arguments (``code``, ``id``, ``authenticator``,
        ``message_authenticator``, ``packet``) and attributes to add,
        with ``-`` in the attribute names replaced by ``_``. The default
        code is Accounting-Request; ``code=pyrad.packet.StatusServer``
        creates a Status-Server packet to the accounting port.

        :return: a new packet
        :rtype:  pyrad.packet.AcctPacket
        """
        return host.Host.CreateAcctPacket(self, secret=self.secret, **args)

    def CreateCoAPacket(self, **args):
        """Create a CoA-Request or Disconnect-Request for this client's server.

        The packet has the dictionary and secret of the client. The
        keyword arguments are passed to :class:`pyrad.packet.CoAPacket`:
        packet arguments (``code``, ``id``, ``authenticator``,
        ``message_authenticator``, ``packet``) and attributes to add,
        with ``-`` in the attribute names replaced by ``_``. The default
        code is CoA-Request, pass ``code=pyrad.packet.DisconnectRequest``
        for a Disconnect-Request.

        :return: a new packet
        :rtype:  pyrad.packet.CoAPacket
        """
        return host.Host.CreateCoAPacket(self, secret=self.secret, **args)

    def _UpdateAcctDelayTime(self, pkt):
        """Add the time waited for a reply to the Acct-Delay-Time of an
        accounting request that is sent again. This is skipped if the
        dictionary does not define Acct-Delay-Time."""
        dictionary = getattr(pkt, 'dict', None)
        if dictionary is None or 'Acct-Delay-Time' not in dictionary:
            return
        if 'Acct-Delay-Time' in pkt:
            pkt['Acct-Delay-Time'] = pkt['Acct-Delay-Time'][0] + self.timeout
        else:
            pkt['Acct-Delay-Time'] = self.timeout

    def _VerifyReply(self, pkt, reply, rawreply, authenticators):
        """Verify a reply against the Request Authenticators of all
        attempts of the request, newest first.

        :return: whether the reply is valid, and the Request Authenticator
                 of the attempt it replies to
        :rtype:  (bool, bytes) tuple
        """
        current = getattr(pkt, 'authenticator', None)
        for authenticator in reversed(authenticators):
            if authenticator == current:
                valid = pkt.VerifyReply(reply, rawreply, enforce_ma=self.enforce_ma)
            else:
                pkt.authenticator = authenticator
                try:
                    valid = pkt.VerifyReply(reply, rawreply, enforce_ma=self.enforce_ma)
                finally:
                    pkt.authenticator = current
            if valid:
                return (True, authenticator)
        return (False, None)

    def _SendPacket(self, pkt, port):
        """Send a packet to a RADIUS server.

        :param pkt:  the packet to send
        :type pkt:   pyrad.packet.Packet
        :param port: UDP port to send packet to
        :type port:  int
        :return:     the reply packet received
        :rtype:      pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        self._SocketOpen()

        # Request Authenticators of all attempts of this request, oldest
        # first. They differ if the packet changes between attempts
        # (Acct-Delay-Time), and a late reply to an earlier attempt is still
        # a valid reply.
        authenticators = []

        for attempt in range(self.retries):
            if attempt and pkt.code == packet.AccountingRequest:
                self._UpdateAcctDelayTime(pkt)

            now = time.monotonic()
            waitto = now + self.timeout

            self._socket.sendto(pkt.RequestPacket(), (self.server, port))
            authenticator = getattr(pkt, 'authenticator', None)
            if authenticator in authenticators:
                authenticators.remove(authenticator)
            authenticators.append(authenticator)

            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)

                if ready:
                    rawreply = self._socket.recv(4096)
                else:
                    now = time.monotonic()
                    continue

                try:
                    reply = pkt.CreateReply(packet=rawreply)
                    (valid, authenticator) = self._VerifyReply(
                        pkt, reply, rawreply, authenticators)
                    if valid:
                        if hasattr(pkt, 'authenticator'):
                            reply.request_authenticator = authenticator
                        return reply
                except packet.PacketError:
                    pass

                now = time.monotonic()

        raise Timeout

    def _SendEapMd5Packet(self, pkt):
        """Authenticate with EAP-MD5 (RFC 3748 section 5.4) over RADIUS
        (RFC 3579).

        The EAP-Response/Identity carries the User-Name. The password is
        the cleartext value of the User-Password attribute of the packet,
        which is only used for the MD5 response: it is removed while the
        requests are sent, because it would be sent in clear and RFC 3579
        section 3.3 doesn't allow User-Password together with EAP-Message.

        :param pkt: the Access-Request with User-Name and User-Password
        :type pkt:  pyrad.packet.AuthPacket
        :return:    the reply packet received
        :rtype:     pyrad.packet.Packet
        :raise ValueError: User-Name or User-Password is missing
        :raise Timeout: RADIUS server does not reply
        """
        (password, user_password) = _EapMd5Identity(pkt)
        try:
            reply = self._SendPacket(pkt, self.authport)
            if not _EapMd5Response(pkt, reply, password):
                return reply
            # RFC 2865 section 4.4: the Access-Request answering an
            # Access-Challenge has a new Identifier
            previous_id = pkt.id
            while pkt.id == previous_id:
                pkt.id = pkt.CreateID()
            return self._SendPacket(pkt, self.authport)
        finally:
            pkt[2] = user_password

    def SendPacket(self, pkt):
        """Send a request to the RADIUS server and wait for a valid reply.

        The port depends on the packet class: an
        :class:`~pyrad.packet.AuthPacket` (also a Status-Server created
        with :meth:`CreateAuthPacket`) is sent to ``authport``, a
        :class:`~pyrad.packet.CoAPacket` to ``coaport`` and any other
        packet (also a Status-Server :class:`~pyrad.packet.AcctPacket`) to
        ``acctport``.

        The request is sent at most ``retries`` times, waiting
        ``timeout`` seconds for a reply after each send. Invalid
        replies are ignored: a wrong Response Authenticator or
        Message-Authenticator, a Proxy-State that was not sent, or a
        missing Message-Authenticator with ``enforce_ma``. Before an
        Accounting-Request is sent again, its Acct-Delay-Time is increased
        by ``timeout`` (this modifies ``pkt``).

        With ``auth_type='eap-md5'`` the client authenticates with
        EAP-MD5 (RFC 3748, RFC 3579): the EAP-Response/Identity carries
        the User-Name, and User-Password holds the cleartext password,
        which is used for the MD5 response but not sent. The
        Access-Challenge of the server is answered automatically, so
        ``pkt`` ends up with an EAP-Message, the State of the challenge
        and a new id.

        :param pkt: the request to send
        :type  pkt: pyrad.packet.Packet
        :return:    the reply; check ``reply.code``, e.g. Access-Accept or
                    Access-Reject
        :rtype:     pyrad.packet.Packet
        :raise Timeout: no valid reply was received
        :raise ValueError: ``auth_type='eap-md5'`` without User-Name or
                           User-Password, or an attribute value that cannot
                           be encoded
        :raise OSError: the socket fails, e.g. the server name cannot be
                        resolved
        """
        if isinstance(pkt, packet.AuthPacket):
            if pkt.auth_type == 'eap-md5':
                return self._SendEapMd5Packet(pkt)
            return self._SendPacket(pkt, self.authport)
        elif isinstance(pkt, packet.CoAPacket):
            return self._SendPacket(pkt, self.coaport)
        else:
            return self._SendPacket(pkt, self.acctport)
