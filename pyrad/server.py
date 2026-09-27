# server.py
#
# Copyright 2003-2004,2007,2016 Wichert Akkerman <wichert@wiggy.net>

import select
import socket
from pyrad import host
from pyrad import packet
import logging


logger = logging.getLogger('pyrad')


class RemoteHost:
    """Remote RADIUS capable host we can talk to."""

    def __init__(self, address, secret, name, authport=1812, acctport=1813, coaport=3799):
        """Constructor.

        :param   address: IP address
        :type    address: string
        :param    secret: RADIUS secret
        :type     secret: bytes
        :param      name: short name (used for logging only)
        :type       name: string
        :param  authport: port used for authentication packets
        :type   authport: integer
        :param  acctport: port used for accounting packets
        :type   acctport: integer
        :param   coaport: port used for CoA packets
        :type    coaport: integer
        """
        self.address = address
        self.secret = secret
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport
        self.name = name


class ServerPacketError(Exception):
    """Exception class for bogus packets.
    ServerPacketError exceptions are only used inside the Server class to
    abort processing of a packet.
    """


def CheckMessageAuthenticator(pkt, enforce_ma=False):
    """Check the Message-Authenticator of a received Access-Request
    (BlastRADIUS countermeasure, CVE-2024-3596).

    :param pkt:        received packet with secret set
    :type  pkt:        Packet class instance
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


class Server(host.Host):
    """Basic RADIUS server.
    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.

    :ivar  hosts: hosts who are allowed to talk to us
    :type  hosts: dictionary mapping IP to RemoteHost class instances
    :ivar  _poll: poll object for network sockets
    :type  _poll: select.poll class instance
    :ivar _fdmap: map of file descriptors to network sockets
    :type _fdmap: dictionary
    :cvar MaxPacketSize: maximum size of a RADIUS packet
    :type MaxPacketSize: integer
    """
    MaxPacketSize = 8192

    def __init__(self, addresses=[], authport=1812, acctport=1813, coaport=3799,
                 hosts=None, dict=None, auth_enabled=True, acct_enabled=True, coa_enabled=False,
                 enforce_ma=False, enable_pkt_verify=True):
        """Constructor.

        :param     addresses: IP addresses to listen on
        :type      addresses: sequence of strings
        :param      authport: port to listen on for authentication packets
        :type       authport: integer
        :param      acctport: port to listen on for accounting packets
        :type       acctport: integer
        :param       coaport: port to listen on for CoA packets
        :type        coaport: integer
        :param         hosts: hosts who we can talk to, a host with the
                              address 0.0.0.0 is used for all other clients
        :type          hosts: dictionary mapping IP to RemoteHost class instances
        :param          dict: RADIUS dictionary to use
        :type           dict: Dictionary class instance
        :param  auth_enabled: enable auth server (default True)
        :type   auth_enabled: bool
        :param  acct_enabled: enable accounting server (default True)
        :type   acct_enabled: bool
        :param   coa_enabled: enable CoA server (default False)
        :type    coa_enabled: bool
        :param    enforce_ma: drop Access-Requests without Message-Authenticator
                              (default False, an invalid Message-Authenticator
                              is always dropped)
        :type     enforce_ma: bool
        :param enable_pkt_verify: drop accounting, CoA and Disconnect requests
                                  with an invalid request authenticator
                                  (default True)
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
        """Use getaddrinfo to lookup all addresses for each address.

        Returns a list of tuples or an empty list:
          [(family, address)]

        :param addr: IP address to lookup
        :type  addr: string
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
        """Add an address to listen on a specific interface.
        String "0.0.0.0" indicates you want to listen on all interfaces.

        :param addr: IP address to listen on
        :type  addr: string
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
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overridden in
        derived classes to add custom behaviour. Send the reply with
        SendReplyPacket(pkt.fd, reply).

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def HandleAcctPacket(self, pkt):
        """Accounting packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overridden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def HandleCoaPacket(self, pkt):
        """CoA packet handler.
        This is an empty function that is called when a valid
        CoA packet has been received. It can be overridden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def HandleDisconnectPacket(self, pkt):
        """Disconnect packet handler.
        This is an empty function that is called when a valid
        Disconnect packet has been received. It can be overridden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def _AddSecret(self, pkt):
        """Add secret to packets received and raise ServerPacketError
        for unknown hosts.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        if pkt.source[0] in self.hosts:
            pkt.secret = self.hosts[pkt.source[0]].secret
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
        :type  pkt: Packet class instance
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
        :type  pkt: Packet class instance
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
        :type  pkt: Packet class instance
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
        :type  fd: socket class instance
        :return: RADIUS packet
        :rtype:  Packet class instance
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
        """Prepare all sockets to receive packets.
        """
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
        reply.source = pkt.source
        return reply

    def _ProcessInput(self, fd):
        """Process available data.
        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls _HandleAuthPacket(), _HandleAcctPacket() or
        _HandleCoaPacket() depending on which socket is being processed.

        :param  fd: socket to read packet from
        :type   fd: socket class instance
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
        """Main loop.
        This method is the main loop for a RADIUS server. It waits
        for packets to arrive via the network and calls other methods
        to process them. Invalid packets are dropped and logged, and so are
        packets for which a handler raises an exception, so that a
        malformed packet can't stop the server.
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
