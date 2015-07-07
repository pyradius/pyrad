#!/usr/bin/python

from pyrad import dictionary, packet, server
from netaddr import *
import logging
import sys, os, signal

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

        ip = str(IPAddress("192.%s.0.0" % x) + self.ips)
        self.ips += 1

        reply=self.CreateReplyPacket(pkt, **{ \
            "Service-Type": "Framed-User", \
            "Framed-IP-Address" : ip, \
            "Framed-IPv6-Prefix" : "2003::1/64"
        })
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


def sigterm_handler(_signo, _stack_frame):
    if os.getpid() == mainPid:
        for p in srv._processes:
            logging.debug("Terminate process with pid %s" % p.pid)
            p.terminate()
    sys.exit(0)


if __name__ == '__main__':

    # register sigterm handler
    signal.signal(signal.SIGTERM, sigterm_handler)

    global mainPid
    mainPid = os.getpid()

    # create server and read dictionary
    global srv
    srv=FakeServer(dict=dictionary.Dictionary("dictionary"))

    # add clients (address, secret, name, authport=1812, acctport=1813)
    srv.hosts["127.0.0.1"]=server.RemoteHost(\
                                            "127.0.0.1", \
                                            "Kah3choteereethiejeimaeziecumi", \
                                            "localhost")
    srv.BindToAddress("")

    # start server with 8 processes but wihtout joining them
    srv.Run(8, False)

    # main loop
    while True:
        # auto restart all processes
        for i in range(len(srv._processes)):
            _p = srv._processes[i]
            if not _p.is_alive():
                pname = _p.name
                x = pname.split("-")[1]
                _p = Process(target=srv._run, name=pname, args=(x,))
                _p.start()
                srv._processes[i] = _p
        time.sleep(10)
