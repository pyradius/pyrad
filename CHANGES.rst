Changelog
=========

Unreleased
----------

Breaking changes
~~~~~~~~~~~~~~~~

Check these before upgrading from 2.5.4. Details follow under Changes.

* Requirements: Python 3.10 or later; building from source needs
  setuptools 77 or later. The ``test`` and ``docs`` extras are replaced by
  dependency groups, so ``pip install pyrad[test]`` no longer installs
  pytest.
* Packets on the wire change:

  * Access-Request and Status-Server packets of Client and ClientAsync,
    and replies to them built with CreateReply(), carry a
    Message-Authenticator as first attribute; it shows up in ``keys()``.
    Pass ``message_authenticator=False`` to leave it out.
  * Status-Server packets built with AcctPacket get a random Request
    Authenticator and a Message-Authenticator, as RFC 5997 requires,
    instead of an Accounting-Request style authenticator.
    AcctPacket.VerifyAcctRequest() verifies the Message-Authenticator of
    Status-Server packets and fails without one, so code that calls it on
    Status-Server packets doesn't accept those of pyrad 2.5.4 clients, and
    pyrad 2.5.4 doesn't accept those of this version. The pyrad servers
    don't answer Status-Server, and Status-Server on the authentication
    port is not affected.
  * CreateReply() copies the Proxy-State attributes of the request. A
    handler that copies them itself sends them twice, and the client
    rejects that reply.
  * An untagged Tunnel-Password is sent with the tag 0.

* Packets that were accepted before are dropped:

  * Servers verify the Request Authenticator of Accounting-, CoA- and
    Disconnect-Requests (the Twisted integration: Accounting-Requests) by
    default (``enable_pkt_verify=True``). Clients whose secret doesn't
    match, e.g. accepted with a catch-all ``0.0.0.0`` hosts entry, are no
    longer served; pass ``enable_pkt_verify=False`` to accept them.
  * Servers drop Access-Requests with an invalid Message-Authenticator;
    this cannot be disabled. In ServerAsync enable_pkt_verify no longer
    affects Access-Requests.
  * Clients discard replies with an invalid Message-Authenticator or with
    a Proxy-State the request didn't have, so the request times out.
  * ``enforce_ma`` of the clients now requires a Message-Authenticator in
    replies to Access-Request and Status-Server; it no longer adds one to
    requests (that is the default now).
  * The blocking Server no longer passes Accounting-Response packets on
    the accounting port to HandleAcctPacket.
  * A Vendor-Specific attribute containing a malformed vendor TLV makes
    the whole packet invalid (PacketError).

* Attribute values read from packets change:

  * Tagged attributes (RFC 2868): ``pkt['Tunnel-Type']`` returns the
    values, e.g. ``['L2TP']`` instead of ``16777219`` with the tag in the
    high octet, and the tag is stripped from string values. A received
    string value of a tagged attribute starting with an octet up to 0x1F
    is read as tag and value (RFC 2868).
  * Values of ``string`` attributes that are not valid UTF-8 are returned
    as bytes instead of str with replacement characters. This applies to
    every string attribute (e.g. a Latin-1 Calling-Station-Id), not only
    User-Password.
  * Undefined TLV sub-attributes are returned keyed by their code instead
    of raising KeyError. A Vendor-Specific attribute whose sub-attribute
    lengths don't add up is kept as raw value of attribute 26.
  * ``pkt['Name'] = value``, ``pkt['Name']``, ``in`` and ``del`` of a TLV
    sub-attribute use its TLV instead of a top-level attribute with the
    sub-attribute's code.
  * ``PwCrypt('')`` returns 16 octets instead of none.

* Exception types change:

  * Values out of range or too long for their type or attribute raise
    ValueError instead of struct.error, which is not a subclass of
    ValueError.
  * Dictionary errors raise ParseError instead of ValueError, TypeError,
    KeyError or struct.error. ParseError is not a subclass of ValueError.
  * AddAttribute with a key that is not a name raises TypeError instead of
    AttributeError. PwDecrypt and SaltDecrypt of a value with a wrong
    length raise PacketError.
  * Decoding a value with the wrong length (e.g. integer, ipaddr,
    ipv6prefix) raises ValueError instead of struct.error or returning a
    wrong value.
  * ipaddr attributes reject IPv6 addresses, and strings longer than 253
    octets in UTF-8 are rejected.

* Dictionaries:

  * Attributes pyrad cannot encode correctly are skipped with a warning
    instead of being loaded: vendors with a format other than 1,1 (e.g.
    USR, Lucent, Starent, WiMAX, Kineto, Alcatel-ESAM), nested TLVs (also
    TLV-typed sub-attributes, which loaded before), arrays (also those
    with has_tag or encrypt, which loaded before) and others. Code using
    them gets KeyError; see Dictionary.skipped_attributes.
  * A sub-attribute of a TLV of another vendor makes the dictionary fail
    to load with ParseError instead of being attached to the wrong TLV.
  * Reading a dictionary that skips attributes logs a warning on the
    ``pyrad`` logger.

* Servers and clients:

  * Client with ``auth_type='eap-md5'``: the EAP-Identity is the User-Name
    instead of the User-Password, the User-Password is not sent, and a
    request without User-Name or User-Password raises ValueError instead
    of using the User-Name as password.
  * An exception raised by a handler of the blocking Server or Proxy is
    logged and the packet dropped; it no longer stops ``Run()``.
  * Proxy passes Access-Challenge, CoA-ACK/NAK and Disconnect-ACK/NAK
    replies to its handlers instead of dropping them.
  * Twisted integration: the RADIUS constructor takes
    ``(hosts=None, dict=None, enforce_ma=False, enable_pkt_verify=True)``,
    hosts must map addresses to RemoteHost instances or secrets, and an
    overridden createPacket is called.
  * ClientAsync: requests pending when the transport is closed fail with
    ConnectionAbortedError (a request nobody awaits logs "Future exception
    was never retrieved"); retransmissions send the bytes of the first
    attempt, so changes to the packet after SendPacket are not sent; a
    request is retried only after ``timeout`` seconds, so a request times
    out after ``(retries + 1) * timeout`` seconds; CreatePacket raises if
    all 256 ids are in use (the Create*Packet methods raise Exception).
  * ClientAsync and ServerAsync: ``loop`` is a property. Without a loop
    passed to the constructor it returns the running loop at the time it
    is used.

Changes
~~~~~~~

* BlastRADIUS (CVE-2024-3596) countermeasures (#200):

  * Clients add a Message-Authenticator to all Access-Request and
    Status-Server packets by default.
  * Clients always verify a Message-Authenticator in replies (enforce_ma
    verified the request instead) and discard replies with unexpected
    Proxy-State attributes.
  * Servers add a Message-Authenticator to all replies to Access-Requests,
    verify it in received Access-Requests and can require it with the new
    enforce_ma option.
  * Message-Authenticator is added as first attribute and verification
    uses the correct authenticator for received replies, including
    CoA/Disconnect ACK/NAK and replies to Status-Server.
  * With enforce_ma, clients require a Message-Authenticator in replies to
    Access-Request and Status-Server packets.

* The FreeRADIUS dictionary files can be read as they are (#173). Attributes
  that pyrad does not support, such as the RFC 6929 extended attributes,
  attributes of the types vsa, ipv4prefix, combo-ip, bool, uint16 and uint32,
  arrays, nested TLVs and attributes of vendors with a format other than
  format=1,1 (e.g. USR, Lucent, Starent, WiMAX, Kineto, Alcatel-ESAM), which
  pyrad encoded as format=1,1 before, are skipped with a warning and listed in
  Dictionary.skipped_attributes. The flags secret and virtual and BEGIN-VENDOR
  with a format= option are accepted. Attributes with the concat flag, such as
  EAP-Message, are loaded as normal attributes instead of being dropped. A
  VALUE for an unknown attribute is ignored with a warning instead of raising a
  ParseError, and a sub-attribute of an unknown TLV raises a ParseError instead
  of a KeyError.
* Fix salt decryption (encrypt=2, e.g. Tunnel-Password) of received
  Accounting-, CoA- and Disconnect-Requests, which used the Request
  Authenticator instead of zeros, and salt encryption of these requests
  after RequestPacket() was called. An Access-Request with salt encrypted
  attributes got an all-zero Request Authenticator, so the User-Password
  encryption was the same in every request; it gets a random one now.
* Fix crashes on malformed or unusual packets: a vendor TLV that was not
  the first sub-attribute of a Vendor-Specific attribute, or that appeared
  in more than one, raised AttributeError while decoding, which stopped
  the blocking server with a single unauthenticated packet. An empty TLV
  made VerifyReply raise ValueError instead of rejecting a forged reply,
  and reading a TLV with an undefined sub-attribute raised KeyError
  (undefined sub-attributes are returned as raw values keyed by their
  code now). PwDecrypt raises PacketError for a password that is not a
  multiple of 16 octets instead of IndexError.
* The blocking Server (and Proxy) drops and logs packets for which a
  handler raises an exception, instead of stopping the main loop, like
  ServerAsync does. Unexpected exceptions while decoding a packet are
  treated as a broken packet.
* ClientAsync: a request cancelled by the caller, e.g. with
  asyncio.wait_for, or a failing retransmission killed the timeout
  handler, so no later request on that transport was retried or timed out
  and they waited forever. A packet that could not be encoded was left
  pending and killed the timeout handler when it expired. Requests that
  are still pending when the transport is closed fail with
  ConnectionAbortedError instead of waiting forever.
* ClientAsync and ServerAsync created without a loop use the running
  event loop instead of calling asyncio.get_event_loop() in the
  constructor, which fails outside of a running loop on Python 3.14.
  ``loop`` is a property that returns the running loop when it is used.
* Client:

  * Timeouts use a monotonic clock, so a step of the system clock no
    longer extends the wait for a reply.
  * A late reply to an earlier attempt of an Accounting-Request, whose
    Request Authenticator changed with Acct-Delay-Time, is accepted
    instead of timing out. Retrying an Accounting-Request no longer fails
    with KeyError if the dictionary has no Acct-Delay-Time.
  * The EAP-MD5 challenge response only hashes the Value of the challenge,
    so challenges with a Name work, and the Access-Request answering the
    Access-Challenge has a new Identifier and Request Authenticator
    (RFC 2865 section 4.4).
  * EAP-MD5 works with FreeRADIUS: the EAP-Identity is the User-Name
    instead of the password, which was sent in clear (#151), and the
    cleartext User-Password is only used for the MD5 response instead of
    being sent in clear with the EAP-Message, which RFC 3579 section 3.3
    doesn't allow. Challenges without State, EAP packets split over
    several EAP-Message attributes and challenges of other EAP types (which
    are returned) are handled.
  * A Client without a dictionary can send Access-Requests again.

* ClientAsync and ServerAsync:

  * initialize_transports can be retried after a transport failed to open
    (e.g. a DNS or bind error) or the call was cancelled (e.g. by
    asyncio.wait_for); the failed or closed transport stayed registered.
  * ClientAsync doesn't hand out the id of a pending request, so more than
    256 requests over time no longer fail with "Packet with id N already
    present"; it raises only if all 256 ids are in use. CreatePacket
    accepts the id 0.
  * ClientAsync timeouts use a monotonic clock, and the dates in
    pending_requests are time.monotonic() values.
  * ClientAsync retransmits the bytes encoded for the first attempt
    instead of encoding the packet again.
  * Transports are opened on platforms without SO_REUSEPORT (e.g.
    Windows), and ClientAsync binds to local_addr also without a local
    port.
  * The ClientAsync retries documentation is corrected (a request is sent
    up to retries + 1 times) and the asyncio examples work on Python 3.14.

* Servers and Proxy:

  * IPv4 clients of a dual stack server bound to '::' (source
    ::ffff:a.b.c.d) are matched against their IPv4 hosts entry, in Server,
    Proxy, ServerAsync and the Twisted integration.
  * Proxy accepts Access-Challenge, CoA-ACK/NAK and Disconnect-ACK/NAK
    replies on the proxy socket instead of dropping them.
  * Twisted integration (pyrad.curved): packets are decoded with the
    packet class of RADIUSAccess/RADIUSAccounting (an overridden
    createPacket that returns None gets a generic packet) and get the client's
    secret, the Message-Authenticator of Access-Requests (BlastRADIUS) and
    the Request Authenticator of Accounting-Requests are verified (new
    enforce_ma and enable_pkt_verify arguments), and the default hosts and
    dictionary are no longer shared between instances. The hosts must map
    to RemoteHost instances or to the secrets; packets of hosts without a
    secret, e.g. given as a set or list of addresses, are dropped and
    logged.
  * Twisted integration: exceptions raised by packet handlers (including
    pyrad.packet.PacketError and ServerPacketError) or by createPacket are
    now dropped and logged, like in Server.Run and ServerAsync. Packets
    that fail to decode are logged with one line, without a traceback.

* Packets:

  * Received packets longer than their Length field are accepted, the
    extra octets are ignored as padding (RFC 2865 section 3).
  * VerifyReply(reply) without rawreply verifies a received reply with the
    bytes it was decoded from, instead of rejecting and modifying it.
  * PwCrypt encrypts an empty password as 16 octets and raises ValueError
    for passwords longer than 128 octets (RFC 2865 section 5.2).
  * Values too long for an attribute, a Vendor-Specific or TLV wrapper or
    salt encryption raise ValueError instead of struct.error, and a TLV
    whose first sub-attributes are long is no longer preceded by an empty
    TLV.
  * Setting a TLV sub-attribute with ``pkt['Name'] = value`` stores it in
    its TLV; it was sent as a top-level attribute with the sub-attribute's
    code. Getting, testing (``in``) and deleting a sub-attribute by name
    use its TLV as well, instead of a top-level attribute with the same
    code.
  * VerifyChapPasswd returns False without CHAP-Password instead of
    raising TypeError, and compares in constant time.
  * Status-Server built with AcctPacket gets a random Request
    Authenticator and a valid Message-Authenticator, and replies to it are
    signed with its Request Authenticator (RFC 5997). VerifyAcctRequest
    verifies the Message-Authenticator of Status-Server packets.
  * A packet created without a dictionary has ``dict`` set to None (unless
    its class defines one), so CreateReply() of such a received packet
    works.
  * The VerifyAuthRequest documentation says what it checks.

* Attribute values:

  * ipaddr values reject IPv6 addresses with ValueError instead of
    encoding 16 octets (RFC 8044 section 3.8).
  * The 253 octet limit of string values is checked on the UTF-8 encoded
    value.
  * ipv6prefix values given as netaddr.IPNetwork clear the host bits and
    reject IPv4 networks, like str values.
  * Out of range integer, signed, short, byte, integer64 and date values
    raise ValueError instead of struct.error.
  * Ascend binary filters raise ValueError if an address doesn't match the
    filter family instead of producing a malformed filter, and terms may
    be separated by any whitespace.
  * The ifid (e.g. Framed-Interface-Id, RFC 3162) and ether types can be
    encoded and decoded.

* Dictionaries:

  * TLV sub-attributes are no longer attached to a TLV with the same code
    of another vendor (the dictionary fails to load with ParseError), and
    TLVs defined in one dictionary file are found
    by sub-attributes in another.
  * Malformed attribute codes, vendor codes and VALUE definitions raise
    ParseError with file and line instead of ValueError, TypeError or
    struct.error. VALUE definitions for date attributes work.
  * A dictionary file that includes itself raises ParseError instead of
    looping forever, and the FreeRADIUS ``$INCLUDE-`` directive (include
    if the file exists) is supported.
  * A redefined attribute or value name is no longer decoded to its old
    name (stale BiDict reverse entries). Deleting a BiDict value removes
    all keys mapping to it, and deleting one of several keys of a value
    keeps the reverse entry of the others.

* The package metadata declares the license as the SPDX expression
  BSD-3-Clause (PEP 639); building requires setuptools 77 or later. The
  test and docs extras are replaced by the dependency groups of the same
  names (``uv sync --all-groups`` or ``pip install --group test``).
* The FreeRADIUS dictionary of the examples is an attributed excerpt of
  the current FreeRADIUS dictionary (CC-BY 4.0), and names attribute 182
  FreeRADIUS-Queue-PPS-Out instead of FreeRADIUS-Queue-PPS-In.
* Fix an infinite loop when decoding a vendor-specific or TLV sub-attribute
  with a length of 0, which let a single unauthenticated packet hang a
  server (#234). Truncated TLVs raise a PacketError instead of struct.error.
* Fix salt decryption of values longer than 16 bytes, such as
  MS-MPPE-Send-Key, MS-MPPE-Recv-Key and long Tunnel-Passwords.
* Fix PwDecrypt of the decoded User-Password attribute, which failed since
  2.5 because invalid UTF-8 was decoded with replacement characters
  (#232, #192). Values of all string attributes that are not valid UTF-8
  are returned as bytes now.
* Fix ServerAsync dropping all Access-Requests with enable_pkt_verify=True
  (#178). enable_pkt_verify no longer applies to Access-Requests, whose
  Message-Authenticator is always verified.
* Fix decoding of tagged attributes (RFC 2868). The tag is stripped from
  the values, ``pkt['Tunnel-Type']`` returns the values of all tags and
  ``pkt['Tunnel-Type:1']`` the values with tag 1. Decoding a tagged
  Tunnel-Password no longer fails, and an untagged Tunnel-Password is sent
  with the mandatory tag 0. A Tunnel-Password without tag, as sent by older
  pyrad versions, is still decoded. An untagged string value starting with
  an octet up to 0x1F is sent with the tag 0, so that it isn't read as tag.
* Fix ClientAsync decrypting salt encrypted reply attributes, such as
  Tunnel-Password and MS-MPPE-Send-Key, with the wrong authenticator.
* Copy Proxy-State attributes into replies (RFC 2865 section 5.33).
* Decoding an integer, signed, short, byte, date, integer64, ipaddr or
  ipv6prefix attribute with a value of the wrong length, or an ipv6addr
  attribute with a value longer than 16 octets, raises a ValueError instead
  of struct.error or returning a wrong value, such as an IPv6 address for a
  16 byte ipaddr value (#13). Shorter ipv6addr values are still padded with
  zeros.
* AddAttribute raises a TypeError with a clear message when the key is not
  an attribute name, e.g. when the key and value arguments are swapped
  (#17).
* Fix encoding of binary octets values starting with b"0x", such as a
  CHAP-Password with CHAP ID 48, which failed with "Odd-length string" or
  "Non-hexadecimal digit found". Bytes values are only decoded as hex if
  the rest of the value is valid hex (#49).
* Fix the length of CoA and Disconnect requests with Message-Authenticator.
* Fix ClientAsync retrying and timing out requests before the timeout passed.
* Verify the request authenticator of Accounting, CoA and Disconnect requests
  by default. The blocking ``Server`` never verified them and ``ServerAsync``
  only with ``enable_pkt_verify=True``; both now default to verification and
  can opt out with ``enable_pkt_verify=False``. ``Server`` no longer accepts
  Accounting-Response packets on the accounting port.
* Drop support for Python 3.8 and 3.9, which are end of life; pyrad requires
  Python 3.10 or later.
* Replace deprecated datetime.utcnow() and Logger.warn calls in the asyncio
  client and server.
* Fix the examples in the README, the docs and the package docstring.
* Add a usage guide to the documentation (attributes, tagged and encrypted
  attributes, accounting, CoA, Status-Server, servers and asyncio) and the
  API documentation of ClientAsync and ServerAsync.
* The dictionary parse error for an attribute definition with a wrong
  number of fields now includes the file name.
* Fix wrong and missing parameter types and descriptions in the docstrings
  (secrets and raw packets are bytes, AddAttribute only takes attribute
  names) and document the asyncio transport and handler methods.

2.5.4 - Feb 5, 2026
-------------------

* remove python2 leftovers
* add support for Ascend-Data-Filter "delete" keyword

2.5.2 - Jan 29, 2026
--------------------

* Fix readthedocs

2.5.1 - Jan 29, 2026
--------------------

* Fix build and release infra

2.5.0 - Jan 29, 2026
--------------------

* Drop support of Python 2.x

* Add salt decryption of encrypted attributes

* Fix #194 salt-encryption

* Fix #213 EncodeIPv6Prefix

* Fix for UTF-8

* Fix usage of socket.getaddrinfo

* Fix #197 KeyError when handling CoA packet for 0.0.0.0

* Fix create CoA packet in client_async

* Fix #152 and add corresponding unittests

* Fixed unittests

2.4 - Nov 23, 2020
------------------

* Support poetry for building this project

* Use secrets.SystemRandom instead of random.SystemRandom if possible

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
-----------------

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
  are unfortunately no longer supported. If you use Python 2.5 or older
  Pyrad 1.2 will still work for you.


1.2 - July 12, 2009
-------------------

* Setup sphinx based documentation.

* Use hashlib instead of md5, if present. This fixes deprecation warnings
  for python 2.6. Patch from Jeremy Liané.

* Support parsing VENDOR format specifications in dictionary files. Patch by
  Kristoffer Grönlund.

* Support $INCLUDE directives in dictionary files. Patch by
  Kristoffer Grönlund.

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

* The proxy server has been moved out of the server module to a new
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

* Allow specifying new attributes when using
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

* Create separate AuthPacket and AcctPacket classes; this resulted in
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
