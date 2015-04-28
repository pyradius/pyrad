#!/usr/bin/python

from pyrad import dictionary, packet, server
from netaddr import *
import logging

logging.basicConfig(filename="pyrad.log", level="DEBUG",
    format = "%(asctime)s [%(levelname)-8s] %(message)s")

class FakeServer(server.Server):

    ips = 0

    def _HandleAuthPacket(self, pkt, x):
        server.Server._HandleAuthPacket(self, pkt)

        print ("Received an authentication request")
        print ("Attributes: ")
        for attr in pkt.keys():
            print ("%s: %s" % (attr, pkt[attr]))

        ip = str(IPAddress("13.%s.0.0" % x) + self.ips)
        self.ips += 1

        reply=self.CreateReplyPacket(pkt, **{ 'Service-Type': 'Framed-User', \
            "Framed-IP-Address" : ip, "Framed-IPv6-Prefix" : "2003::1/64", \
             "ERX-Service-Activate:1" : "SRL(200,200)", \
             'X-Ascend-Data-Filter': ['family=ipv4 action=discard direction=in dst=10.10.255.254/32 sport=200 sportq=2', 'family=ipv6 action=discard direction=in src=fe80::/64 dst=2003::/19 dport=1337' ]})
        reply.code=packet.AccessAccept
        self.SendReplyPacket(pkt.fd, reply)

    def _HandleAcctPacket(self, pkt, x):
        server.Server._HandleAcctPacket(self, pkt)

        print ("Received an accounting request")
        print ("Attributes: ")
        for attr in pkt.keys():
            print ("%s: %s" % (attr, pkt[attr]))

        reply=self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)


srv=FakeServer(dict=dictionary.Dictionary("dictionary"))
srv.hosts["127.0.0.1"]=server.RemoteHost("127.0.0.1",
                                         "Kah3choteereethiejeimaeziecumi",
                                         "localhost")
srv.hosts["172.30.138.10"]=server.RemoteHost("172.30.138.10", "jun01%#", "imme")
srv.BindToAddress("")
srv.Run(4)
