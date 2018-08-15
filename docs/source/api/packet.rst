:mod:`pyrad.packet` -- packet encoding and decoding
===================================================

.. automodule:: pyrad.packet

  .. autoclass:: Packet
    :members:

  .. autoclass:: AuthPacket
    :members:

  .. autoclass:: AcctPacket
    :members:

  .. autoclass:: CoAPacket
    :members:

  .. autoclass:: PacketError
    :members:


Constants
---------

The :mod:`pyrad.packet` module defines several common constants
that are useful when dealing with RADIUS packets.

The following packet codes are defined:

==================    ======
Constant name         Value
==================    ======
AccessRequest         1
------------------    ------
AccessAccept          2
AccessReject          3
AccountingRequest     4
AccountingResponse    5
AccessChallenge       11
StatusServer          12
StatusClient          13
DisconnectRequest     40
DisconnectACK         41
DisconnectNAK         42
CoARequest            43
CoAACK                44
CoANAK                45
==================    ======
