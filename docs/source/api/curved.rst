:mod:`pyrad.curved` -- Twisted integration
===========================================

.. automodule:: pyrad.curved

  .. autoclass:: RADIUS(hosts=None, dict=None, enforce_ma=None, enable_pkt_verify=True)
    :members: processPacket, createPacket

  .. autoclass:: RADIUSAccess
    :members: processPacket, createPacket
    :show-inheritance:

  .. autoclass:: RADIUSAccounting
    :members: processPacket, createPacket
    :show-inheritance:

  .. autoclass:: PacketError
