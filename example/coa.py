#!/usr/bin/python
from __future__ import print_function
from pyrad.client import Client
from pyrad import dictionary
from pyrad import packet
import sys

if len(sys.argv) != 3:
  print ("usage: coa.py {coa|dis} daemon-1234")
  sys.exit(1)

ADDRESS = "127.0.0.1"
SECRET = b"Kah3choteereethiejeimaeziecumi"
ATTRIBUTES = {
    "Acct-Session-Id": "1337"
}

ATTRIBUTES["NAS-Identifier"] = sys.argv[2]

# create coa client
client = Client(server=ADDRESS, secret=SECRET, dict=dictionary.Dictionary("dictionary"))

# set coa timeout
client.timeout = 30

# create coa request packet
attributes = {k.replace("-", "_"): ATTRIBUTES[k] for k in ATTRIBUTES}

if sys.argv[1] == "coa":
    # create coa request
    request = client.CreateCoAPacket(**attributes)
elif sys.argv[1] == "dis":
    # create disconnect request
    request = client.CreateCoAPacket(code=packet.DisconnectRequest, **attributes)
else:
  sys.exit(1)

# send request
result = client.SendPacket(request)
print(result)
print(result.code)
