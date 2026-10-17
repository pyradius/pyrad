# host.py
#
# Copyright 2003,2007 Wichert Akkerman <wichert@wiggy.net>
"""Base class with the settings shared by RADIUS clients and servers."""

__docformat__ = "restructuredtext en"

from pyrad import packet


class Host:
    """Generic RADIUS capable host.

    Base class of :class:`pyrad.client.Client` and
    :class:`pyrad.server.Server`, which holds the dictionary and the
    ports and creates packets with this dictionary.

    :ivar     dict: RADIUS dictionary
    :type     dict: pyrad.dictionary.Dictionary
    :ivar authport: the port a server listens on for authentication
                    packets, or the port of the server a client sends
                    them to
    :type authport: int
    :ivar acctport: the port a server listens on for accounting packets,
                    or the port of the server a client sends them to
    :type acctport: int
    :ivar  coaport: the port a server listens on for CoA and Disconnect
                    packets, or the port of the server a client sends
                    them to
    :type  coaport: int
    """
    def __init__(self, authport=1812, acctport=1813, coaport=3799, dict=None):
        """
        :param authport: authentication port, see ``authport``
        :type  authport: int
        :param acctport: accounting port, see ``acctport``
        :type  acctport: int
        :param  coaport: CoA port, see ``coaport``
        :type   coaport: int
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        """
        self.dict = dict
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport

    def CreatePacket(self, **args):
        """Create a generic RADIUS packet with the dictionary of this host.

        The keyword arguments are passed to :class:`pyrad.packet.Packet`:
        packet arguments such as ``code``, ``id``, ``secret``,
        ``authenticator`` or ``packet``, and attributes to add, with
        ``-`` in the attribute names replaced by ``_``.

        :return: a new packet
        :rtype:  pyrad.packet.Packet
        """
        return packet.Packet(dict=self.dict, **args)

    def CreateAuthPacket(self, **args):
        """Create an authentication packet with the dictionary of this host.

        The keyword arguments are passed to
        :class:`pyrad.packet.AuthPacket`: packet arguments (``code``,
        ``id``, ``secret``, ``authenticator``, ``auth_type``,
        ``message_authenticator``, ``packet``) and attributes to add,
        with ``-`` in the attribute names replaced by ``_``
        (``User_Name='alice'``). The default code is Access-Request.

        :return: a new packet
        :rtype:  pyrad.packet.AuthPacket
        """
        return packet.AuthPacket(dict=self.dict, **args)

    def CreateAcctPacket(self, **args):
        """Create an accounting packet with the dictionary of this host.

        The keyword arguments are passed to
        :class:`pyrad.packet.AcctPacket`: packet arguments (``code``,
        ``id``, ``secret``, ``authenticator``, ``message_authenticator``,
        ``packet``) and attributes to add, with ``-`` in the attribute
        names replaced by ``_``. The default code is Accounting-Request.

        :return: a new packet
        :rtype:  pyrad.packet.AcctPacket
        """
        return packet.AcctPacket(dict=self.dict, **args)

    def CreateCoAPacket(self, **args):
        """Create a CoA or Disconnect packet with the dictionary of this host.

        The keyword arguments are passed to
        :class:`pyrad.packet.CoAPacket`: packet arguments (``code``,
        ``id``, ``secret``, ``authenticator``, ``message_authenticator``,
        ``packet``) and attributes to add, with ``-`` in the attribute
        names replaced by ``_``. The default code is CoA-Request, pass
        ``code=pyrad.packet.DisconnectRequest`` for a Disconnect-Request.

        :return: a new packet
        :rtype:  pyrad.packet.CoAPacket
        """
        return packet.CoAPacket(dict=self.dict, **args)

    def SendPacket(self, fd, pkt):
        """Send a request packet to the address in ``pkt.source``.

        The packet is encoded with ``pkt.RequestPacket()``. pyrad doesn't
        use this method itself; :meth:`pyrad.client.Client.SendPacket`
        replaces it.

        :param  fd: socket to send the packet with
        :type   fd: socket.socket
        :param pkt: packet to send
        :type  pkt: pyrad.packet.Packet
        """
        fd.sendto(pkt.RequestPacket(), pkt.source)

    def SendReplyPacket(self, fd, pkt):
        """Send a reply packet to the address in ``pkt.source``.

        The packet is encoded with :meth:`pyrad.packet.Packet.ReplyPacket`.
        A reply created with ``CreateReply`` of a received request has the
        source of the request.

        :param  fd: socket to send the packet with
        :type   fd: socket.socket
        :param pkt: reply packet to send
        :type  pkt: pyrad.packet.Packet
        """
        fd.sendto(pkt.ReplyPacket(), pkt.source)
