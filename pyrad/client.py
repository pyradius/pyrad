# client.py
#
# Copyright 2002-2007 Wichert Akkerman <wichert@wiggy.net>

__docformat__ = "epytext en"

import select
import socket
import time
import six
from pyrad import host
from pyrad import packet


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
    :type timeout: integer
    """
    def __init__(self, server, authport=1812, acctport=1813,
            coaport=3799, secret=six.b(''), dict=None):

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
        :type    secret: string
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        """
        host.Host.__init__(self, authport, acctport, coaport, dict)

        self.server = server
        self.secret = secret
        self._socket = None
        self.retries = 3
        self.timeout = 5
        self._poll = select.poll()

    def bind(self, addr):
        """Bind socket to an address.
        Binding the socket used for communicating to an address can be
        usefull when working on a machine with multiple addresses.

        :param addr: network address (hostname or IP) and port to bind to
        :type  addr: host,port tuple
        """
        self._CloseSocket()
        self._SocketOpen()
        self._socket.bind(addr)

    def _SocketOpen(self):
        try:
            family = socket.getaddrinfo(self.server, 'www')[0][0]
        except:
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

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AuthPacket
        """
        return host.Host.CreateAuthPacket(self, secret=self.secret, **args)

    def CreateAcctPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return host.Host.CreateAcctPacket(self, secret=self.secret, **args)

    def CreateCoAPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return host.Host.CreateCoAPacket(self, secret=self.secret, **args)

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

        for attempt in range(self.retries):
            if attempt and pkt.code == packet.AccountingRequest:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = \
                            pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout

            now = time.time()
            waitto = now + self.timeout

            self._socket.sendto(pkt.RequestPacket(), (self.server, port))

            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)

                if ready:
                    rawreply = self._socket.recv(4096)
                else:
                    now = time.time()
                    continue

                try:
                    reply = pkt.CreateReply(packet=rawreply)
                    if pkt.VerifyReply(reply, rawreply):
                        return reply
                except packet.PacketError:
                    pass

                now = time.time()

        raise Timeout

    def SendPacket(self, pkt):
        """Send a packet to a RADIUS server.

        :param pkt: the packet to send
        :type pkt:  pyrad.packet.Packet
        :return:    the reply packet received
        :rtype:     pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        if isinstance(pkt, packet.AuthPacket):
            return self._SendPacket(pkt, self.authport)
        elif isinstance(pkt, packet.CoAPacket):
            return self._SendPacket(pkt, self.coaport)
        else:
            return self._SendPacket(pkt, self.acctport)
