#!/usr/bin/python

import asyncio

import logging
import traceback
from pyrad.dictionary import Dictionary
from pyrad.client_async import ClientAsync
from pyrad.packet import AccountingResponse

logging.basicConfig(level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")
client = ClientAsync(server="127.0.0.1",
                     secret=b"Kah3choteereethiejeimaeziecumi",
                     timeout=3, debug=True,
                     dict=Dictionary("dictionary"))

loop = asyncio.get_event_loop()


def create_request(client, user):
    req = client.CreateAcctPacket(User_Name=user)

    req["NAS-IP-Address"] = "192.168.1.10"
    req["NAS-Port"] = 0
    req["Service-Type"] = "Login-User"
    req["NAS-Identifier"] = "trillian"
    req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
    req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
    req["Framed-IP-Address"] = "10.0.0.100"

    return req


def print_reply(reply):
    print("Received Accounting-Response")

    print("Attributes returned by server:")
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))


def test_acct1(enable_message_authenticator=False):

    global client

    try:
        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                client.initialize_transports(enable_auth=True,
                                             # local_addr='127.0.0.1',
                                             # local_auth_port=8000,
                                             enable_acct=True,
                                             enable_coa=True)))

        req = create_request(client, "wichert")
        if enable_message_authenticator:
            req.add_message_authenticator()

        future = client.SendPacket(req)

        #    loop.run_until_complete(future)
        loop.run_until_complete(asyncio.ensure_future(
            asyncio.gather(
                future,
                return_exceptions=True
            )

        ))

        if future.exception():
            print('EXCEPTION ', future.exception())
        else:
            reply = future.result()

            if reply.code == AccountingResponse:
                print("Accounting accepted")

            print("Attributes returned by server:")
            for i in reply.keys():
                print("%s: %s" % (i, reply[i]))

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            client.deinitialize_transports()))
        print('END')

        del client
    except Exception as exc:
        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))
        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            client.deinitialize_transports()))

    loop.close()


#test_acct1()
test_acct1(enable_message_authenticator=True)
