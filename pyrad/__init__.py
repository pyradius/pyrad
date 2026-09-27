"""Python RADIUS client and server code.

pyrad is an implementation of a RADIUS client/server as described in RFC 2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses.

Here is an example of doing an authentication request::

  import pyrad.packet
  from pyrad.client import Client
  from pyrad.dictionary import Dictionary

  srv = Client(server="radius.my.domain", secret=b"s3cr3t",
               dict=Dictionary("dicts/dictionary", "dictionary.acc"))

  req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                             User_Name="wichert", NAS_Identifier="localhost")
  req["User-Password"] = req.PwCrypt("password")

  reply = srv.SendPacket(req)
  if reply.code == pyrad.packet.AccessAccept:
      print("access accepted")
  else:
      print("access denied")

  print("Attributes returned by server:")
  for key in reply.keys():
      print(f"{key}: {reply[key]}")


This package contains the following modules:

  - client: RADIUS client code
  - client_async: asyncio based RADIUS client code
  - server: RADIUS server code
  - server_async: asyncio based RADIUS server code
  - proxy: RADIUS proxy server code
  - curved: Twisted based RADIUS client and server code
  - host: base class for RADIUS clients and servers
  - dictionary: RADIUS attribute dictionary
  - dictfile: dictionary file parser with $INCLUDE support
  - packet: a RADIUS packet as sent to/from servers
  - tools: utility functions
"""

__docformat__ = 'epytext en'

__author__ = 'Christian Giese <gic@gicnet.de>'
__url__ = 'http://pyrad.readthedocs.io/en/latest/?badge=latest'
__copyright__ = 'Copyright 2002-2026 Wichert Akkerman, Christian Giese, Istvan Ruzman and Stefan Lieberth. All rights reserved.'
__version__ = '2.5.4'

__all__ = ['client', 'dictionary', 'packet', 'server', 'tools', 'dictfile']
