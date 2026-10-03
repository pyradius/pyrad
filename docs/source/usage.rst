*****
Usage
*****

Dictionaries
============

pyrad needs a RADIUS dictionary to translate attribute names to their
codes and data types. It reads dictionaries in the FreeRADIUS format,
including ``$INCLUDE``, ``VENDOR``, ``BEGIN-VENDOR``/``END-VENDOR``,
``VALUE`` and the attribute flags ``has_tag`` and ``encrypt=1`` or
``encrypt=2``. The ``example`` directory of the source distribution has a
dictionary with the standard attributes to start from. A dictionary can be
made of several files:

.. code-block:: python

    from pyrad.dictionary import Dictionary

    dictionary = Dictionary("dictionary", "dictionary.vendor")

The dictionary has to define every attribute that you want to use by
name. Attributes which are not defined can still be sent and received
as raw values (see `Attributes`_).

Secrets
=======

Shared secrets are ``bytes``, for example ``secret=b"testing123"``.
Passing a ``str`` raises a ``TypeError``.

Attributes
==========

Packets behave like a dictionary which maps attribute names to lists of
values, because RADIUS allows an attribute to be repeated. pyrad keeps the
order of attributes when it encodes and decodes a packet.

.. code-block:: python

    req = client.CreateAuthPacket(User_Name="alice", NAS_Port=1)

    req["NAS-Identifier"] = "nas01"             # set, replacing existing values
    req["Reply-Message"] = ["first", "second"]  # set several values
    req.AddAttribute("Reply-Message", "third")  # append a value

    req["User-Name"]            # ['alice']
    "NAS-Port" in req           # True
    req.get("Class", [])        # [] if the attribute is missing
    del req["Reply-Message"]

    for name in req.keys():     # attribute names, as far as they are known
        print(name, req[name])

* Keyword arguments of the ``Create*Packet`` methods are attribute names
  with ``-`` replaced by ``_``.
* Values are converted according to the attribute type in the dictionary:
  ``str`` for ``string`` and addresses, ``int`` for ``integer`` and
  ``date``, ``bytes`` for ``octets``. For attributes with ``VALUE``
  definitions the value names are used, such as
  ``Service_Type="Framed-User"``.
* Vendor-specific attributes are used by name like any other attribute.
* Attributes can also be accessed by their code, or by a
  ``(vendor, code)`` tuple for vendor-specific attributes. This works
  with the raw encoded values (``bytes``), which is how you send and
  receive attributes that are not defined in the dictionary:
  ``req[26] = [raw_vsa]``, ``reply[(9, 1)]``.
* ``Packet.items()`` and ``values()`` are the underlying raw codes and
  values. Use ``keys()`` and ``pkt[name]`` for the decoded values.

Tagged attributes
-----------------

Attributes with the ``has_tag`` flag (RFC 2868), such as the tunnel
attributes used for dynamic VLAN assignment, take a tag between 0 and 31
after the name:

.. code-block:: python

    reply.AddAttribute("Tunnel-Type:1", "VLAN")
    reply.AddAttribute("Tunnel-Medium-Type:1", "IEEE-802")
    reply.AddAttribute("Tunnel-Private-Group-Id:1", "100")

    reply["Tunnel-Private-Group-Id"]    # values of all tags: ['100']
    reply["Tunnel-Private-Group-Id:1"]  # values with tag 1: ['100']

Accessing a tag which is not present raises a ``KeyError``, like a
missing attribute.

Encrypted attributes
--------------------

The User-Password of Access-Requests (``encrypt=1``) has to be encrypted
explicitly with :meth:`~pyrad.packet.AuthPacket.PwCrypt`. A server
decrypts it with :meth:`~pyrad.packet.AuthPacket.PwDecrypt`:

.. code-block:: python

    req["User-Password"] = req.PwCrypt("password")

    password = pkt.PwDecrypt(pkt["User-Password"][0])  # in a server

Attributes with ``encrypt=2`` (RFC 2868 and RFC 2548), such as
Tunnel-Password and the MS-MPPE keys, are encrypted and decrypted
automatically. The clients take care of the request authenticator that
is needed to decrypt them in replies.

Clients
=======

Authentication
--------------

Create a :class:`~pyrad.client.Client` and send the packets created with
it. :meth:`~pyrad.client.Client.SendPacket` retries the request and
raises :class:`~pyrad.client.Timeout` if the server does not reply.
Replies are verified, invalid replies are ignored.

.. code-block:: python

    import pyrad.packet
    from pyrad.client import Client, Timeout
    from pyrad.dictionary import Dictionary

    client = Client(server="localhost", secret=b"testing123",
                    dict=Dictionary("dictionary"), timeout=3, retries=3)

    req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                  User_Name="alice")
    req["User-Password"] = req.PwCrypt("password")

    try:
        reply = client.SendPacket(req)
    except Timeout:
        print("RADIUS server does not reply")
    else:
        if reply.code == pyrad.packet.AccessAccept:
            print("access accepted")
        else:
            print("access denied")

For CHAP (RFC 2865 section 2.2) send a CHAP-Password and a CHAP-Challenge
instead of the User-Password:

.. code-block:: python

    import hashlib
    import os

    req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                  User_Name="alice")
    chap_id = os.urandom(1)
    challenge = os.urandom(16)
    req["CHAP-Challenge"] = challenge
    req["CHAP-Password"] = chap_id + hashlib.md5(
        chap_id + b"password" + challenge).digest()
    reply = client.SendPacket(req)

Status-Server
-------------

Status-Server (RFC 5997) checks if a server is alive. It is sent to the
authentication port and answered with an Access-Accept:

.. code-block:: python

    reply = client.SendPacket(
        client.CreateAuthPacket(code=pyrad.packet.StatusServer))

Accounting
----------

.. code-block:: python

    req = client.CreateAcctPacket(User_Name="alice")
    req["Acct-Status-Type"] = "Start"
    req["Acct-Session-Id"] = "1234"
    reply = client.SendPacket(req)  # an AccountingResponse

When an accounting request is retried the client adds the time waited so
far to the Acct-Delay-Time attribute.

CoA and Disconnect
------------------

Change-of-Authorization and Disconnect requests (RFC 5176) are sent to
the ``coaport`` (3799) of the NAS:

.. code-block:: python

    nas = Client(server="nas.example.com", secret=b"testing123",
                 dict=Dictionary("dictionary"))

    req = nas.CreateCoAPacket(User_Name="alice", Session_Timeout=3600)
    reply = nas.SendPacket(req)  # CoAACK or CoANAK

    req = nas.CreateCoAPacket(code=pyrad.packet.DisconnectRequest,
                              User_Name="alice")
    reply = nas.SendPacket(req)  # DisconnectACK or DisconnectNAK

asyncio
-------

:class:`~pyrad.client_async.ClientAsync` sends several requests at the
same time. ``SendPacket`` returns a future, which raises a
``TimeoutError`` if the server does not reply. Packets can only be
created after ``initialize_transports`` enabled the transport for them:

.. code-block:: python

    import asyncio

    import pyrad.packet
    from pyrad.client_async import ClientAsync
    from pyrad.dictionary import Dictionary

    async def main():
        client = ClientAsync(server="localhost", secret=b"testing123",
                             dict=Dictionary("dictionary"),
                             loop=asyncio.get_running_loop())
        await client.initialize_transports(enable_auth=True, enable_acct=True)
        try:
            requests = []
            for user in ("alice", "bob"):
                req = client.CreateAuthPacket(User_Name=user)
                req["User-Password"] = req.PwCrypt("password")
                requests.append(client.SendPacket(req))
            for reply in await asyncio.gather(*requests):
                print(reply.code == pyrad.packet.AccessAccept)
        finally:
            await client.deinitialize_transports()

    asyncio.run(main())

Servers
=======

Derive from :class:`~pyrad.server.Server` and override the handlers of
the requests you want to answer. Requests are only accepted from the
clients in ``hosts``, which maps an IP address to a
:class:`~pyrad.server.RemoteHost` with its secret. A host with the
address ``0.0.0.0`` is used for all other clients.

.. code-block:: python

    import pyrad.packet
    from pyrad.dictionary import Dictionary
    from pyrad.server import RemoteHost, Server

    class MyServer(Server):
        def HandleAuthPacket(self, pkt):
            reply = self.CreateReplyPacket(pkt, Reply_Message="Hello")
            reply.code = pyrad.packet.AccessReject
            if pkt.get("User-Name") == ["alice"] and "User-Password" in pkt:
                if pkt.PwDecrypt(pkt["User-Password"][0]) == "password":
                    reply.code = pyrad.packet.AccessAccept
            self.SendReplyPacket(pkt.fd, reply)

        def HandleAcctPacket(self, pkt):
            self.SendReplyPacket(pkt.fd, self.CreateReplyPacket(pkt))

    hosts = {"127.0.0.1": RemoteHost("127.0.0.1", b"testing123", "localhost")}
    server = MyServer(addresses=["127.0.0.1"], hosts=hosts,
                      dict=Dictionary("dictionary"))
    server.Run()

``Run`` only catches errors of invalid packets: an exception raised by a
handler stops the server, so handlers must cope with missing attributes.

The authentication (1812) and accounting (1813) ports are enabled by
default. CoA and Disconnect requests are received with
``coa_enabled=True`` and the handlers ``HandleCoaPacket`` and
``HandleDisconnectPacket``. The reply to a CoA request is a CoAACK; set
``reply.code`` to answer with a NAK or to acknowledge a Disconnect
request with ``pyrad.packet.DisconnectACK``.

Before a handler is called the server drops invalid requests:

* requests from unknown clients
* requests with an invalid Message-Authenticator, and Access-Requests
  without one unless ``enforce_ma=False`` (see :ref:`blastradius`)
* Accounting, CoA and Disconnect requests with an invalid request
  authenticator, which proves that the client knows the secret. This
  check can be disabled with ``enable_pkt_verify=False``.

asyncio
-------

:class:`~pyrad.server_async.ServerAsync` has to implement all four
handlers, which send their reply with ``protocol.send_response``:

.. code-block:: python

    import asyncio

    import pyrad.packet
    from pyrad.dictionary import Dictionary
    from pyrad.server import RemoteHost
    from pyrad.server_async import ServerAsync

    class MyServer(ServerAsync):
        def handle_auth_packet(self, protocol, pkt, addr):
            reply = self.CreateReplyPacket(pkt, Reply_Message="Hello")
            reply.code = pyrad.packet.AccessAccept
            protocol.send_response(reply, addr)

        def handle_acct_packet(self, protocol, pkt, addr):
            protocol.send_response(self.CreateReplyPacket(pkt), addr)

        def handle_coa_packet(self, protocol, pkt, addr):
            protocol.send_response(self.CreateReplyPacket(pkt), addr)

        def handle_disconnect_packet(self, protocol, pkt, addr):
            reply = self.CreateReplyPacket(pkt)
            reply.code = pyrad.packet.DisconnectACK
            protocol.send_response(reply, addr)

    async def main():
        hosts = {"127.0.0.1": RemoteHost("127.0.0.1", b"testing123", "localhost")}
        server = MyServer(hosts=hosts, dictionary=Dictionary("dictionary"),
                          loop=asyncio.get_running_loop())
        await server.initialize_transports(enable_auth=True, enable_acct=True,
                                           enable_coa=True,
                                           addresses=["127.0.0.1"])
        try:
            await asyncio.Event().wait()  # serve until cancelled
        finally:
            await server.deinitialize_transports()

    asyncio.run(main())
