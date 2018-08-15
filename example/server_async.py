#!/usr/bin/python

import asyncio

import logging
import traceback
from pyrad.dictionary import Dictionary
from pyrad.server_async import ServerAsync
from pyrad.packet import AccessAccept
from pyrad.server import RemoteHost

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except:
    pass

logging.basicConfig(level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")

class FakeServer(ServerAsync):

    def __init__(self, loop, dictionary):

        ServerAsync.__init__(self, loop=loop, dictionary=dictionary,
                             enable_pkt_verify=True, debug=True)


    def handle_auth_packet(self, protocol, pkt, addr):

        print("Received an authentication request with id ", pkt.id)
        print('Authenticator ', pkt.authenticator.hex())
        print('Secret ', pkt.secret)
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt, **{
            "Service-Type": "Framed-User",
            "Framed-IP-Address": '192.168.0.1',
            "Framed-IPv6-Prefix": "fc66::1/64"
        })

        reply.code = AccessAccept
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):

        print("Received an accounting request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_coa_packet(self, protocol, pkt, addr):

        print("Received an coa request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):

        print("Received an disconnect request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        protocol.send_response(reply, addr)


if __name__ == '__main__':

    # create server and read dictionary
    loop = asyncio.get_event_loop()
    server = FakeServer(loop=loop, dictionary=Dictionary('dictionary'))

    # add clients (address, secret, name)
    server.hosts["127.0.0.1"] = RemoteHost("127.0.0.1",
                                           b"Kah3choteereethiejeimaeziecumi",
                                           "localhost")

    try:

        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                server.initialize_transports(enable_auth=True,
                                             enable_acct=True,
                                             enable_coa=True)))

        try:
            # start server
            loop.run_forever()
        except KeyboardInterrupt as k:
            pass

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    except Exception as exc:
        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))
        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    loop.close()
