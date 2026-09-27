# client.py
#
# Copyright 2002-2007 Wichert Akkerman <wichert@wiggy.net>

__docformat__ = "epytext en"

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


class Timeout(Exception):
    """Simple exception class which is raised when a timeout occurs
    while waiting for a RADIUS server to respond."""


class Client(host.Host):
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.

    :ivar retries: number of times to retry sending a RADIUS request
    :type retries: integer
    :ivar timeout: number of seconds to wait for an answer
    :type timeout: float
    """
    def __init__(self, server, authport=1812, acctport=1813,
                 coaport=3799, secret=b'', dict=None, retries=3, timeout=5, enforce_ma=False):
        """Constructor.

        :param   server: hostname or IP address of RADIUS server
        :type    server: string
        :param authport: port to use for authentication packets
        :type  authport: integer
        :param acctport: port to use for accounting packets
        :type  acctport: integer
        :param coaport: port to use for CoA packets
        :type  coaport: integer
        :param   secret: RADIUS secret
        :type    secret: bytes
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        :param  retries: number of times to send a request
        :type   retries: integer
        :param  timeout: number of seconds to wait for a reply
        :type   timeout: float
        :param enforce_ma: Require a Message-Authenticator in replies to
                           Access-Request and Status-Server packets (a
                           Message-Authenticator in a reply is always
                           verified)
        :type  enforce_ma: boolean
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
        """Bind socket to an address.
        Binding the socket used for communicating to an address can be
        useful when working on a machine with multiple addresses.

        :param addr: network address (hostname or IP) and port to bind to
        :type  addr: host,port tuple
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
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        A Message-Authenticator is added by default as countermeasure
        against the BlastRADIUS attack (CVE-2024-3596), which can be
        disabled with message_authenticator=False.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AuthPacket
        """
        args.setdefault('message_authenticator', True)
        return host.Host.CreateAuthPacket(self, secret=self.secret, **args)

    def CreateAcctPacket(self, **args):
        """Create a new accounting RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AcctPacket
        """
        return host.Host.CreateAcctPacket(self, secret=self.secret, **args)

    def CreateCoAPacket(self, **args):
        """Create a new CoA RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
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
        :type port:  integer
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

    def SendPacket(self, pkt):
        """Send a packet to a RADIUS server.
        Authentication packets are sent to the authport, CoA and
        Disconnect packets to the coaport and accounting packets to the
        acctport. The request is retried until a valid reply is received;
        invalid replies are ignored.

        :param pkt: the packet to send
        :type pkt:  pyrad.packet.Packet
        :return:    the reply packet received
        :rtype:     pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        if isinstance(pkt, packet.AuthPacket):
            if pkt.auth_type == 'eap-md5':
                # Creating EAP-Identity
                password = pkt[2][0] if 2 in pkt else pkt[1][0]
                pkt[79] = [struct.pack('!BBHB%ds' % len(password),
                                       EAP_CODE_RESPONSE,
                                       packet.CurrentID,
                                       len(password) + 5,
                                       EAP_TYPE_IDENTITY,
                                       password)]
            reply = self._SendPacket(pkt, self.authport)
            if (
                reply
                and reply.code == packet.AccessChallenge
                and pkt.auth_type == 'eap-md5'
            ):
                # Got an Access-Challenge
                eap_code, eap_id, eap_size, eap_type, eap_md5 = struct.unpack(
                    '!BBHB%ds' % (len(reply[79][0]) - 5), reply[79][0]
                )
                # Sending back an EAP-Type-MD5-Challenge
                # Thank god for http://www.secdev.org/python/eapy.py
                client_pw = pkt[2][0] if 2 in pkt else pkt[1][0]
                # RFC 3748 section 5.4: Type-Data is Value-Size, Value and
                # an optional Name
                value = eap_md5[1:1 + eap_md5[0]] if eap_md5 else b''
                md5_challenge = hashlib.md5(
                    struct.pack('!B', eap_id) + client_pw + value
                ).digest()
                pkt[79] = [
                    struct.pack('!BBHBB', 2, eap_id, len(md5_challenge) + 6,
                                4, len(md5_challenge)) + md5_challenge
                ]
                # Copy over Challenge-State
                pkt[24] = reply[24]
                reply = self._SendPacket(pkt, self.authport)
            return reply
        elif isinstance(pkt, packet.CoAPacket):
            return self._SendPacket(pkt, self.coaport)
        else:
            return self._SendPacket(pkt, self.acctport)
