#!/usr/bin/python
from __future__ import print_function
from pyrad.client import Client
from pyrad import dictionary
from pyrad import packet

ADDRESS = "127.0.0.1"
SECRET = b"Kah3choteereethiejeimaeziecumi"
ATTRIBUTES = {
    "Acct-Session-Id": "1337"
}

# create coa client
client = Client(server=ADDRESS, secret=SECRET, dict=dictionary.Dictionary("dictionary"))

# set coa timeout
client.timeout = 30

# create coa request packet
attributes = {k.replace("-", "_"): ATTRIBUTES[k] for k in ATTRIBUTES}

# create coa request
request = client.CreateCoAPacket(**attributes)
# create disconnect request
# request = client.CreateCoAPacket(code=packet.DisconnectRequest, **attributes)

# send request
result = client.SendPacket(request)
print(result)
print(result.code)
