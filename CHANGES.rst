Changelog
=========

2.4 - Nov 23, 2020
-------------------

* Support poetry for for building this project

* Use secrets.SysRandom instead of random.SystemRandom if possible

* `.get` on Packets has an optional default parameter (to mimic dict.get())

* Fix: digestmod is not optional in python3.8 anymore

* Fix: authenticator was refreshed before the packet was generated

* Fix bug causing Message-Authenticator verification to fail if
  multiple instances of an attribute do not appear sequentially in
  the attributes list

* Fixed #140 VerifyReply broken when multiple instances of same attribute are
  not adjacent on reply

* Fixed #135 Missing send_packet for async Client

* Fixed #126 python3 support for SaltCrypt
  (was previously broken)

2.3 - Feb 6, 2020
------------------

* Fixed #124 remove reuse_address=True from async server/client

* Fixed #121 Unknown attribute key error

2.2 - Oct 19, 2019
------------------

* Add message authenticator support (attribute 80)

* Add support for multiple values of the same attribute (#95)

* Add experimental async client and server implementation for python >=3.5.

* Add IPv6 bind support for client and server.

* Add support of tlv and integer64 attributes.

* Multiple minor enhancements and fixes.

2.1 - Feb 2, 2017
-----------------

* Add CoA support (client and server).

* Add tagged attribute support (send only).

* Add salt encryption support (encrypt 2).

* Add ascend data filter support (human readable format to octets).

* Add ipv6 address and prefix support.

* Add support for octet strings in hex (starting with 0x).

* Add support for types short, signed and byte.

* Add support for VSA's with multiple sub TLV's.

* Use a different random generator to improve the security of generated
  packet ids and authenticators.


2.0 - May 15, 2011
------------------

* Start moving codebase to PEP8 compatible coding style.

* Add support for Python 3.2.

* Several code cleanups. As a side effect Python versions before 2.6
  are unfortunatley no longer supported. If you use Python 2.5 or older
  Pyrad 1.2 will still work for you.


1.2 - July 12, 2009
-------------------

* Setup sphinx based documentation.

* Use hashlib instead of md5, if present. This fixes deprecation warnings
  for python 2.6. Patch from Jeremy Liané.

* Support parsing VENDOR format specifications in dictionary files. Patch by
  Kristoffer Grönlun.

* Supprt $INCLUDE directores in dictionary files. Patch by
  Kristoffer Grönlun.

* Standardize on 4 spaces for indents. Patch by Kristoffer Grönlund/
  Purplescout.

* Make sure all encoding utility methods raise a TypeError if a value of
  the wrong type is passed in.


1.1 - September 30, 2007
------------------------

* Add the 'octets' datatype from FreeRADIUS. This is treated just like string;
  the only difference is how FreeRADIUS prints it.

* Check against unimplemented datatypes in EncodeData and DecodeData instead
  of assuming an identity transform works.

* Make Packet.has_key and __contains__ gracefully handle unknown attributes.
  Based on a patch from Alexey V Michurun <am@rol.ru>.

* Add a __delitem__ implementation to Packet. Based on a patch from
  Alexey V Michurun <am@rol.ru>.


1.0 - September 16, 2007
------------------------

* Add unit tests. Pyrad now has 100% test coverage!

* Moved the proxy server has been out of the server module to a new
  proxy module.

* Fix several errors that prevented the proxy code from working.

* Use the standard logging module instead of printing to stdout.

* The default dictionary for Server instances was shared between all
  instances, possibly leading to unwanted data pollution. Each Server now
  gets its own dict instance if none is passed in to the constructor.

* Fixed a timeout handling problem in the client: after receiving an
  invalid reply the current time was not updated, possibly leading to
  the client blocking forever.

* Switch to setuptools, allowing pyrad to be distributed as an egg
  via the python package index.

* Use absolute instead of relative imports.

* Sockets are now opened with SO_REUSEADDR enabled to allow for faster
  restarts.


0.9 - April 25, 2007
------------------------

* Start using trac to manage the project: http://code.wiggy.net/tracker/pyrad/

* [bug 3] Fix handling of packets with an id of 0

* [bug 2] Fix handling of file descriptor parameters in the server
  code and example.

* [bug 4] Fix wrong variable name in exception raised when encountering
  an overly long packet.

* [bug 5] Fix error message in parse error for dictionaries.

* [bug 8] Packet.CreateAuthenticator is now a static method.


0.8
---

* Fix time-handling in the client packet sending code: it would loop
  forever since the now time was updated at the wrong moment. Fix from
  Michael Mitchell <Michael.Mitchell@team.telstra.com>

* Fix passing of dict parameter when creating reply packets


0.7
---

* add HandleAuthPacket and HandleAcctPacket hooks to Server class.
  Request from Thomas Boettcher.

* Pass on dict attribute when creating a reply packet. Requested by
  Thomas Boettcher.

* Allow specififying new attributes when using
  Server.CreateReplyPacket. Requested by Thomas Boettcher.


0.6
---

* packet.VerifyReply() had a syntax error when not called with a raw packet.

* Add bind() method to the Client class.

* [SECURITY] Fix handling of timeouts in client module: when a bad
  packet was received pyrad immediately started the next retry instead of
  discarding it and waiting for a timeout. This could be exploited by
  sending a number of bogus responses before a correct reply to make pyrad
  not see the real response.

* correctly set Acct-Delay-Time when resending accounting requests packets.

* verify account request packages as well (from Farshad Khoshkhui).

* protect against packets with bogus lengths (from Farshad Khoshkhui).


0.5
---

* Fix typo in server class which broke handling of accounting packets.

* Create seperate AuthPacket and AcctPacket classes; this resulted in
  a fair number of API changes.

* Packets now know how to create and verify replies.

* Client now directs authentication and accounting packets to the
  correct port on the server.

* Add twisted support via the new curved module.

* Fix incorrect exception handling in client code.

* Update example server to handle accounting packets.

* Add example for sending account packets.


0.4
---

* Fix last case of bogus exception usage.

* Move RADIUS code constants to packet module.

* Add support for decoding passwords and generating reply packets to Packet
  class.

* Add basic RADIUS server and proxy implementation.


0.3
---

* client.Timeout is now derived from Exception.

* Docstring documentation added.

* Include example dictionaries and authentication script.


0.2
---

* Use proper exceptions.

* Encode and decode vendor attributes.

* Dictionary can parse vendor dictionaries.

* Dictionary can handle attribute values.

* Enhance most constructors; they now take extra optional parameters
  with initialisation info.

* No longer use obsolete python interfaces like whrandom.


0.1
---

* First release
