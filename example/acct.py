#!/usr/bin/python
from __future__ import print_function
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import random
import socket
import sys
import pyrad.packet


def SendPacket(srv, req):
    try:
        srv.SendPacket(req)
    except pyrad.client.Timeout:
        print("RADIUS server does not reply")
        sys.exit(1)
    except socket.error as error:
        print("Network error: " + error[1])
        sys.exit(1)

srv = Client(server="localhost", secret=b"Kah3choteereethiejeimaeziecumi", dict=Dictionary("dictionary"))

req = srv.CreateAcctPacket(User_Name="wichert")

req["NAS-IP-Address"] = "192.168.1.10"
req["NAS-Port"] = 0
req["NAS-Identifier"] = "trillian"
req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
req["Framed-IP-Address"] = "10.0.0.100"

print("Sending accounting start packet")
req["Acct-Status-Type"] = "Start"
SendPacket(srv, req)

print("Sending accounting stop packet")
req["Acct-Status-Type"] = "Stop"
req["Acct-Input-Octets"] = random.randrange(2**10, 2**30)
req["Acct-Output-Octets"] = random.randrange(2**10, 2**30)
req["Acct-Session-Time"] = random.randrange(120, 3600)
req["Acct-Terminate-Cause"] = random.choice(["User-Request", "Idle-Timeout"])
SendPacket(srv, req)
