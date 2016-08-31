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
CODE = packet.CoARequest                # 43
# CODE = packet.DisconnectRequest       # 40

# create coa client
client = Client(server=ADDRESS, secret=SECRET, authport=3799, acctport=3799, dict=dictionary.Dictionary("dictionary"))
# set coa timeout
client.timeout = 30

# create coa request packet
attributes = {k.replace("-", "_"): attributes[k] for k in attributes}
request = client.CreateAcctPacket(code=CODE, **attributes)

# send coa request
result = client.SendPacket(request)
print(result)
