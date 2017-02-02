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
        :type     secret: string
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


class Server(host.Host):
    """Basic RADIUS server.
    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.

    :ivar  hosts: hosts who are allowed to talk to us
    :type  hosts: dictionary of Host class instances
    :ivar  _poll: poll object for network sockets
    :type  _poll: select.poll class instance
    :ivar _fdmap: map of filedescriptors to network sockets
    :type _fdmap: dictionary
    :cvar MaxPacketSize: maximum size of a RADIUS packet
    :type MaxPacketSize: integer
    """
    MaxPacketSize = 8192

    def __init__(self, addresses=[], authport=1812, acctport=1813, coaport=3799,
                 hosts=None, dict=None, auth_enabled=True, acct_enabled=True, coa_enabled=False):
        """Constructor.

        :param     addresses: IP addresses to listen on
        :type      addresses: sequence of strings
        :param      authport: port to listen on for authentication packets
        :type       authport: integer
        :param      acctport: port to listen on for accounting packets
        :type       acctport: integer
        :param       coaport: port to listen on for CoA packets
        :type        coaport: integer
        :param         hosts: hosts who we can talk to
        :type          hosts: dictionary mapping IP to RemoteHost class instances
        :param          dict: RADIUS dictionary to use
        :type           dict: Dictionary class instance
        :param  auth_enabled: enable auth server (default True)
        :type   auth_enabled: bool
        :param  acct_enabled: enable accounting server (default True)
        :type   acct_enabled: bool
        :param   coa_enabled: enable coa server (default False)
        :type    coa_enabled: bool
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

        for addr in addresses:
            self.BindToAddress(addr)

    def BindToAddress(self, addr):
        """Add an address to listen to.
        An empty string indicated you want to listen on all addresses.

        :param addr: IP address to listen on
        :type  addr: string
        """
        if self.auth_enabled:
            authfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            authfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            authfd.bind((addr, self.authport))
            self.authfds.append(authfd)

        if self.acct_enabled:
            acctfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            acctfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            acctfd.bind((addr, self.acctport))
            self.acctfds.append(acctfd)

        if self.coa_enabled:
            coafd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            coafd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            coafd.bind((addr, self.coaport))
            self.coafds.append(coafd)


    def HandleAuthPacket(self, pkt):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def HandleAcctPacket(self, pkt):
        """Accounting packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def HandleCoaPacket(self, pkt):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def HandleDisconnectPacket(self, pkt):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """


    def _HandleAuthPacket(self, pkt):
        """Process a packet received on the authentication port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        if pkt.source[0] not in self.hosts:
            raise ServerPacketError('Received packet from unknown host')

        pkt.secret = self.hosts[pkt.source[0]].secret
        if pkt.code != packet.AccessRequest:
            raise ServerPacketError(
                'Received non-authentication packet on authentication port')
        self.HandleAuthPacket(pkt)

    def _HandleAcctPacket(self, pkt):
        """Process a packet received on the accounting port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        if pkt.source[0] not in self.hosts:
            raise ServerPacketError('Received packet from unknown host')

        pkt.secret = self.hosts[pkt.source[0]].secret
        if pkt.code not in [packet.AccountingRequest,
                            packet.AccountingResponse]:
            raise ServerPacketError(
                    'Received non-accounting packet on accounting port')
        self.HandleAcctPacket(pkt)

    def _HandleCoaPacket(self, pkt):
        """Process a packet received on the coa port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        if pkt.source[0] not in self.hosts:
            raise ServerPacketError('Received packet from unknown host')

        pkt.secret = self.hosts[pkt.source[0]].secret
        if pkt.code == packet.CoARequest:
            self.HandleCoaPacket(pkt)
        elif pkt.code == packet.DisconnectRequest:
            self.HandleDisconnectPacket(pkt)
        else:
            raise ServerPacketError('Received non-coa packet on coa port')


    def _GrabPacket(self, pktgen, fd):
        """Read a packet from a network connection.
        This method assumes there is data waiting for to be read.

        :param fd: socket to read packet from
        :type  fd: socket class instance
        :return: RADIUS packet
        :rtype:  Packet class instance
        """
        (data, source) = fd.recvfrom(self.MaxPacketSize)
        pkt = pktgen(data)
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
        """
        reply = pkt.CreateReply(**attributes)
        reply.source = pkt.source
        return reply

    def _ProcessInput(self, fd):
        """Process available data.
        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls either HandleAuthPacket() or
        HandleAcctPacket() depending on which socket is being
        processed.

        :param  fd: socket to read packet from
        :type   fd: socket class instance
        """
        if fd.fileno() in self._realauthfds:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateAuthPacket(packet=data), fd)
            self._HandleAuthPacket(pkt)
        elif fd.fileno() in self._realacctfds:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateAcctPacket(packet=data), fd)
            self._HandleAcctPacket(pkt)
        else:
            pkt = self._GrabPacket(lambda data, s=self: s.CreateCoAPacket(packet=data), fd)
            self._HandleCoaPacket(pkt)

    def Run(self):
        """Main loop.
        This method is the main loop for a RADIUS server. It waits
        for packets to arrive via the network and calls other methods
        to process them.
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
                else:
                    logger.error('Unexpected event in server main loop')
