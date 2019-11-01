#!/usr/bin/python

import asyncio

import logging
import traceback
from pyrad.dictionary import Dictionary
from pyrad.client_async import ClientAsync
from pyrad.packet import AccessAccept

logging.basicConfig(level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")
client = ClientAsync(server="127.0.0.1",
                     secret=b"Kah3choteereethiejeimaeziecumi",
                     timeout=3, debug=True,
                     dict=Dictionary("dictionary"))

loop = asyncio.get_event_loop()


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


def test_auth1():

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

        req = client.CreateAuthPacket(User_Name="wichert")

        req["NAS-IP-Address"] = "192.168.1.10"
        req["NAS-Port"] = 0
        req["Service-Type"] = "Login-User"
        req["NAS-Identifier"] = "trillian"
        req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
        req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        req["Framed-IP-Address"] = "10.0.0.100"

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

            if reply.code == AccessAccept:
                print("Access accepted")
            else:
                print("Access denied")

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


def test_multi_auth():

    global client

    try:
        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                client.initialize_transports(enable_auth=True,
                                             local_addr='127.0.0.1',
                                             # local_auth_port=8000,
                                             enable_acct=True,
                                             enable_coa=True)))

        reqs = []
        for i in range(150):
            req = create_request(client, "user%s" % i)
            print('CREATE REQUEST with id %d' % req.id)
            future = client.SendPacket(req)
            reqs.append(future)

        #    loop.run_until_complete(future)
        loop.run_until_complete(asyncio.ensure_future(
            asyncio.gather(
                *reqs,
                return_exceptions=True
            )

        ))

        for future in reqs:
            if future.exception():
                print('EXCEPTION ', future.exception())
            else:
                reply = future.result()
                print_reply(reply)

        print('INVALID RESPONSE:', client.protocol_auth.errors)
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


def test_multi_client():

    clients = []
    n_clients = 73
    n_req4client = 50
    reqs = []

    global loop

    try:
        for i in range(n_clients):
            client = ClientAsync(server="localhost",
                                 secret=b"Kah3choteereethiejeimaeziecumi",
                                 timeout=4, debug=True,
                                 dict=Dictionary("dictionary"),
                                 loop=loop)

            clients.append(client)

            # Initialize transports
            loop.run_until_complete(
                asyncio.ensure_future(
                    client.initialize_transports(enable_auth=True,
                                                 enable_acct=False,
                                                 enable_coa=False)))

            # Send
            for j in range(n_req4client):
                req = create_request(client, "user%s" % j)
                print('CREATE REQUEST with id %d' % req.id)
                future = client.SendPacket(req)
                reqs.append(future)

        #    loop.run_until_complete(future)
        loop.run_until_complete(asyncio.ensure_future(
            asyncio.gather(
                *reqs,
                return_exceptions=True
            )

        ))

        for future in reqs:
            if future.exception():
                print('EXCEPTION ', future.exception())
            else:
                reply = future.result()
                print_reply(reply)

        client = clients.pop()
        while client:

            print('INVALID RESPONSE:', client.protocol_auth.errors)
            print('RETRIES:', client.protocol_auth.retries_counter)

            loop.run_until_complete(asyncio.ensure_future(
                client.deinitialize_transports()))

            del client
            if len(clients) > 0:
                client = clients.pop()
            else:
                client = None

        print('END')
    except Exception as exc:

        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))

        for client in clients:
            # Close transports
            loop.run_until_complete(asyncio.ensure_future(
                client.deinitialize_transports()))

    loop.close()


def test_auth1_msg_authenticator():
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

            if reply.code == AccessAccept:
                print("Access accepted")
            else:
                print("Access denied")

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


# test_multi_auth()
# test_auth1()
# test_multi_client()
test_auth1_msg_authenticator()
