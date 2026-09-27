
*********************************
:mod:`pyrad` -- RADIUS for Python
*********************************

:Author: Christian Giese (GIC-de), Istvan Ruzman (Istvan91) and Stefan Lieberth (slieberth)
:Version: |version|

Introduction
============

pyrad is an implementation of a RADIUS client/server as described in RFC 2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses.

Here is an example of doing an authentication request::

    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    import pyrad.packet

    srv = Client(server="localhost", secret=b"Kah3choteereethiejeimaeziecumi",
                 dict=Dictionary("dictionary"))

    # create request
    req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                               User_Name="wichert", NAS_Identifier="localhost")
    req["User-Password"] = req.PwCrypt("password")

    # send request
    reply = srv.SendPacket(req)

    if reply.code == pyrad.packet.AccessAccept:
        print("access accepted")
    else:
        print("access denied")

    print("Attributes returned by server:")
    for key in reply.keys():
        print(f"{key}: {reply[key]}")

See :doc:`usage` for more examples.


.. _blastradius:

BlastRADIUS
===========

pyrad implements the countermeasures against the BlastRADIUS attack
(CVE-2024-3596, https://blastradius.fail):

* Clients add a Message-Authenticator as first attribute to all
  Access-Request and Status-Server packets (disable per packet with
  ``message_authenticator=False``).
* A Message-Authenticator in a reply or request is always verified.
  Replies containing Proxy-State attributes which were not sent in the
  request are discarded.
* Servers add a Message-Authenticator as first attribute to all replies to
  Access-Requests and copy the Proxy-State attributes from the request.
* ``Client(enforce_ma=True)`` and ``ClientAsync(enforce_ma=True)`` discard
  replies to Access-Request and Status-Server packets without
  Message-Authenticator, and ``Server(enforce_ma=True)`` and
  ``ServerAsync(enforce_ma=True)`` drop Access-Requests without
  Message-Authenticator. This is recommended if all peers support it.

Requirements & Installation
===========================

pyrad requires Python 3.10 or later.

pyrad is available on PyPI and can be installed with pip::

  pip install pyrad

To install from a source checkout, run the following in the project directory::

  pip install .

Author, Copyright, Availability
===============================

pyrad was written by Wichert Akkerman <wichert@wiggy.net> and is maintained by
Christian Giese (GIC-de), Istvan Ruzman (Istvan91) and Stefan Lieberth (slieberth).

We’re looking for contributors to support the pyrad team! If you’re interested in
helping with development, testing, documentation, or other areas, please contact
us directly.

This project is licensed under a BSD license.

Copyright and license information can be found in the LICENSE.txt file.

The current version and documentation can be found on PyPI:
https://pypi.org/project/pyrad/

Bugs and wishes can be submitted in the pyrad issue tracker on GitHub:
https://github.com/pyradius/pyrad/issues

Related Projects & Forks
========================

**pyrad2:** Noteworthy fork with experimental RadSec (RFC 6614) support. Targets Python 3.12+,
adds extensive type hints, boosts test coverage, and includes fresh bug fixes.
https://github.com/nicholasamorim/pyrad2

**pyrad-server:** Lab-grade RADIUS test server built on top of pyrad.
https://github.com/slieberth/pyrad-server

Usage
=====

.. toctree::
  :maxdepth: 2

  usage

API Documentation
=================

Per-module :mod:`pyrad` API documentation.

.. toctree::
  :maxdepth: 2

  api/client
  api/client_async
  api/dictionary
  api/host
  api/packet
  api/proxy
  api/server
  api/server_async


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
