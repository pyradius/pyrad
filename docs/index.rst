.. _index:

*********************************
:mod:`pyrad` -- RADIUS for Python
*********************************

:Author: Wichert Akkerman
:Version: |version|

.. module:: pyrad

Introduction
============

pyrad is an implementation of a RADIUS client as described in RFC2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses. 

Here is an example of doing a authentication request::

  import pyrad.packet
  from pyrad.client import Client
  from pyrad.dictionary import Dictionary

  srv=Client(server="radius.my.domain", secret="s3cr3t",
  	dict=Dictionary("dicts/dictionary", "dictionary.acc"))

  req=srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
  		User_Name="wichert", NAS_Identifier="localhost")
  req["User-Password"]=req.PwCrypt("password")

  reply=srv.SendPacket(req)
  if reply.code==pyrad.packet.AccessAccept:
      print "access accepted"
  else:
      print "access denied"

  print "Attributes returned by server:"
  for i in reply.keys():
      print "%s: %s" % (i, reply[i])


Requirements & Installation
===========================

pyrad requires Python 2.6 or later, or Python 3.2 or later

Installing is simple; pyrad uses the standard distutils system for installing
Python modules::

  python setup.py install


API Documentation
=================

Per-module :mod:`pyrad` API documentation.

.. toctree::
   :maxdepth: 2

   api/client
   api/dictionary
   api/host
   api/packet
   api/proxy
   api/server

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
