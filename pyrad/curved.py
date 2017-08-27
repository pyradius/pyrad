# curved.py
#
# Copyright 2002 Wichert Akkerman <wichert@wiggy.net>

"""Twisted integration code
"""

__docformat__ = 'epytext en'

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log
import sys
from pyrad import dictionary
from pyrad import host
from pyrad import packet


class PacketError(Exception):

  """Exception class for bogus packets

  PacketError exceptions are only used inside the Server class to
  abort processing of a packet.
  """


class RADIUS(host.Host, protocol.DatagramProtocol):

  def __init__(self, hosts={}, dic=dictionary.Dictionary()):
    host.Host.__init__(self, dic=dic)
    self.hosts = hosts

  def process_packet(self, pkt):
    pass

  def create_packet(self, **kwargs):
    raise NotImplementedError('Attempted to use a pure base class')

  def datagram_received(self, datagram, source):
    remote_host, port = source
    try:
      pkt = self.create_packet(packet=datagram)
    except packet.PacketError as err:
      log.msg('Dropping invalid packet: ' + str(err))
      return

    if remote_host not in self.hosts:
      log.msg('Dropping packet from unknown host ' + remote_host)
      return

    pkt.source = (remote_host, port)
    try:
      self.process_packet(pkt)
    except PacketError as err:
      log.msg('Dropping packet from %s: %s' % (remote_host, str(err)))


class RADIUSAccess(RADIUS):

  def create_packet(self, **kwargs):
    self.create_auth_packet(**kwargs)

  def process_packet(self, pkt):
    if pkt.code != packet.ACCESSREQUEST:
      raise PacketError(
        'non-AccessRequest packet on authentication socket')


class RADIUSAccounting(RADIUS):

  def create_packet(self, **kwargs):
    self.create_acct_packet(**kwargs)

  def process_packet(self, pkt):
    if pkt.code != packet.ACCOUNTINGREQUEST:
      raise PacketError(
        'non-AccountingRequest packet on authentication socket')


if __name__ == '__main__':
  log.startLogging(sys.stdout, 0)
  reactor.listenUDP(1812, RADIUSAccess())
  reactor.listenUDP(1813, RADIUSAccounting())
  reactor.run()
