#!/usr/bin/python
from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
import socket
import sys
import pyrad2.packet

srv = Client(server="localhost", authport=18121, secret=b"test", dict=Dictionary("dictionary"))

req = srv.CreateAuthPacket(code=pyrad2.packet.StatusServer)
req["FreeRADIUS-Statistics-Type"] = "All"
req.add_message_authenticator()

try:
    print("Sending FreeRADIUS status request")
    reply = srv.SendPacket(req)
except pyrad2.client.Timeout:
    print("RADIUS server does not reply")
    sys.exit(1)
except socket.error as error:
    print("Network error: " + error[1])
    sys.exit(1)

print("Attributes returned by server:")
for i in reply.keys():
    print("%s: %s" % (i, reply[i]))
