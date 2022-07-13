
.. image:: https://github.com/pyradius/pyrad/workflows/Python%203.X%20test/badge.svg?branch=master
    :target: https://github.com/pyradius/pyrad/actions?query=workflow
.. image:: https://coveralls.io/repos/github/pyradius/pyrad/badge.svg?branch=master
    :target: https://coveralls.io/github/pyradius/pyrad?branch=master
.. image:: https://img.shields.io/pypi/v/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad
.. image:: https://img.shields.io/pypi/pyversions/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad
.. image:: https://img.shields.io/pypi/dm/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad
.. image:: https://readthedocs.org/projects/pyradius-pyrad/badge/?version=latest
    :target: https://pyradius-pyrad.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/l/pyrad.svg
    :target: https://pypi.python.org/pypi/pyrad

Introduction
============

pyrad is an implementation of a RADIUS client/server as described in RFC2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses.

Here is an example of doing a authentication request::

    from __future__ import print_function
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
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))



Requirements & Installation
===========================

pyrad requires Python 2.7, or Python 3.6 or later

Installing is simple; pyrad uses the standard distutils system for installing
Python modules::

  python setup.py install


Author, Copyright, Availability
===============================

pyrad was written by Wichert Akkerman <wichert@wiggy.net> and is maintained by 
Christian Giese (GIC-de) and Istvan Ruzman (Istvan91). 

This project is licensed under a BSD license.

Copyright and license information can be found in the LICENSE.txt file.

The current version and documentation can be found on pypi:
https://pypi.org/project/pyrad/

Bugs and wishes can be submitted in the pyrad issue tracker on github:
https://github.com/pyradius/pyrad/issues
