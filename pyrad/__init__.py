"""Python RADIUS client code.

pyrad is an implementation of a RADIUS client as described in RFC2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses.

Here is an example of doing a authentication request::

  import pyrad.packet
  from pyrad.client import Client
  from pyrad.dictionary import Dictionary

  srv = Client(server="radius.my.domain", secret="s3cr3t",
    dict = Dictionary("dicts/dictionary", "dictionary.acc"))

  req = srv.CreatePacket(code=pyrad.packet.AccessRequest,
        User_Name = "wichert", NAS_Identifier="localhost")
  req["User-Password"] = req.PwCrypt("password")

  reply = srv.SendPacket(req)
  if reply.code = =pyrad.packet.AccessAccept:
      print "access accepted"
  else:
      print "access denied"

  print "Attributes returned by server:"
  for i in reply.keys():
      print "%s: %s" % (i, reply[i])


This package contains four modules:

  - client: RADIUS client code
  - dictionary: RADIUS attribute dictionary
  - packet: a RADIUS packet as send to/from servers
  - tools: utility functions
"""

__docformat__ = 'epytext en'

__author__ = 'Christian Giese <developer@gicnet.de>'
__url__ = 'http://pyrad.readthedocs.io/en/latest/?badge=latest'
__copyright__ = 'Copyright 2002-2019 Wichert Akkerman and Christian Giese. All rights reserved.'
__version__ = '2.2'

__all__ = ['client', 'dictionary', 'packet', 'server', 'tools', 'dictfile']
