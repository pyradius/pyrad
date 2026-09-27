#!/usr/bin/python

import asyncio

import logging
import traceback
from pyrad.dictionary import Dictionary
from pyrad.client_async import ClientAsync
from pyrad.packet import AccessAccept

logging.basicConfig(level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")


def create_client():
    return ClientAsync(server="localhost",
                       secret=b"Kah3choteereethiejeimaeziecumi",
                       timeout=4,
                       dict=Dictionary("dictionary"))


def create_request(client, user):
    req = client.CreateAuthPacket(User_Name=user)

    req["NAS-IP-Address"] = "192.168.1.10"
    req["NAS-Port"] = 0
    req["Service-Type"] = "Login-User"
    req["NAS-Identifier"] = "trillian"
    req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
    req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
    req["Framed-IP-Address"] = "10.0.0.100"

    return req


def print_reply(reply):
    if reply.code == AccessAccept:
        print("Access accepted")
    else:
        print("Access denied")

    print("Attributes returned by server:")
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))


async def test_auth1():
    client = create_client()

    try:
        # Initialize transports
        await client.initialize_transports(enable_auth=True,
                                           local_addr='127.0.0.1',
                                           local_auth_port=8000,
                                           enable_acct=True,
                                           enable_coa=True)

        req = create_request(client, "wichert")

        try:
            reply = await client.SendPacket(req)
        except Exception as exc:
            print('EXCEPTION ', exc)
        else:
            print_reply(reply)

        print('END')

    except Exception as exc:
        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))

    finally:
        # Close transports
        await client.deinitialize_transports()


async def test_multi_auth():
    client = create_client()

    try:
        # Initialize transports
        await client.initialize_transports(enable_auth=True,
                                           local_addr='127.0.0.1',
                                           local_auth_port=8000,
                                           enable_acct=True,
                                           enable_coa=True)

        reqs = []
        for i in range(255):
            req = create_request(client, "user%s" % i)
            reqs.append(client.SendPacket(req))

        replies = await asyncio.gather(*reqs, return_exceptions=True)

        for reply in replies:
            if isinstance(reply, Exception):
                print('EXCEPTION ', reply)
            else:
                print_reply(reply)

        print('END')

    except Exception as exc:
        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))

    finally:
        # Close transports
        await client.deinitialize_transports()


# asyncio.run(test_multi_auth())
asyncio.run(test_auth1())
