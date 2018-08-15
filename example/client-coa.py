#!/usr/bin/python
#
# Copyright 6WIND, 2017
#

from __future__ import print_function
from pyrad import dictionary, packet, server
import sys
import prctl

class FakeCoA(server.Server):

    def HandleCoaPacket(self, pkt):
        """Accounting packet handler.
        Function that is called when a valid
        accounting packet has been received.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        print("Received a coa request %d" % pkt.code)
        print("  Attributes: ")
        for attr in pkt.keys():
            print("  %s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # try ACK or NACK
        # reply.code = packet.CoANAK
        reply.code = packet.CoAACK
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):
        print("Received a disconnect request %d" % pkt.code)
        print("  Attributes: ")
        for attr in pkt.keys():
            print("  %s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # try ACK or NACK
        # reply.code = packet.DisconnectNAK
        reply.code = packet.DisconnectACK
        self.SendReplyPacket(pkt.fd, reply)

if __name__ == '__main__':

    prctl.set_name('radius-FakeCoA-client')

    if len(sys.argv) != 2:
        print ("usage: client-coa.py 3799")
        sys.exit(1)

    bindport=int(sys.argv[1])

    # create server/coa only and read dictionary
    # bind and listen only on 127.0.0.1:argv[1]
    coa = FakeCoA(addresses=["127.0.0.1"], dict=dictionary.Dictionary("dictionary"), coaport=bindport, auth_enabled=False, acct_enabled=False, coa_enabled=True)

    # add peers (address, secret, name)
    coa.hosts["127.0.0.1"] = server.RemoteHost("127.0.0.1", b"Kah3choteereethiejeimaeziecumi", "localhost")

    # start
    coa.Run()
