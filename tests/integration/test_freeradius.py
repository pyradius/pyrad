"""Integration tests for the pyrad clients against FreeRADIUS.

Users and clients are configured in ``tests/integration/freeradius``.
pyrad adds a Message-Authenticator to all Access-Requests by default and
FreeRADIUS 3.2 adds one to all replies (BlastRADIUS countermeasures).
"""
import asyncio
import hashlib
import os
import socket
import time

import pytest

from pyrad import packet
from pyrad.client import Client, Timeout
from pyrad.client_async import ClientAsync

from .conftest import SECRET, SERVER, STRICT_CLIENT


def auth_request(client, user, password, **attributes):
    req = client.CreateAuthPacket(code=packet.AccessRequest,
                                  User_Name=user, **attributes)
    req["User-Password"] = req.PwCrypt(password)
    return req


def chap_request(client, user, password):
    req = client.CreateAuthPacket(code=packet.AccessRequest, User_Name=user)
    chap_id = os.urandom(1)
    challenge = os.urandom(16)
    req["CHAP-Challenge"] = challenge
    req["CHAP-Password"] = chap_id + hashlib.md5(
        chap_id + password.encode() + challenge).digest()
    return req


def test_pap_accept(client):
    reply = client.SendPacket(auth_request(
        client, "alice", "alice-password", NAS_Identifier="pyrad"))
    assert reply.code == packet.AccessAccept
    assert reply["Reply-Message"] == ["Hello, alice"]
    assert reply["Framed-IP-Address"] == ["10.0.0.1"]


def test_pap_long_password(client):
    reply = client.SendPacket(auth_request(
        client, "bob", "a-very-long-password-exceeding-sixteen-octets"))
    assert reply.code == packet.AccessAccept


def test_pap_wrong_password(client):
    reply = client.SendPacket(auth_request(client, "alice", "wrong"))
    assert reply.code == packet.AccessReject


def test_pap_unknown_user(client):
    reply = client.SendPacket(auth_request(client, "mallory", "secret"))
    assert reply.code == packet.AccessReject


def test_chap_accept(client):
    reply = client.SendPacket(chap_request(client, "alice", "alice-password"))
    assert reply.code == packet.AccessAccept


def test_chap_wrong_password(client):
    reply = client.SendPacket(chap_request(client, "alice", "wrong"))
    assert reply.code == packet.AccessReject


def test_enforce_message_authenticator(dictionary):
    client = Client(server=SERVER, secret=SECRET, dict=dictionary,
                    retries=2, timeout=2, enforce_ma=True)
    req = client.CreateAuthPacket(code=packet.AccessRequest, User_Name="alice")
    req["User-Password"] = req.PwCrypt("alice-password")
    reply = client.SendPacket(req)
    assert reply.code == packet.AccessAccept
    assert "Message-Authenticator" in reply


def test_proxy_state_is_echoed(dictionary):
    client = Client(server=SERVER, secret=SECRET, dict=dictionary,
                    retries=2, timeout=2, enforce_ma=True)
    req = auth_request(client, "alice", "alice-password",
                       Proxy_State=[b"first", b"second"])
    reply = client.SendPacket(req)
    assert reply.code == packet.AccessAccept
    assert reply["Proxy-State"] == [b"first", b"second"]


def test_require_message_authenticator(dictionary):
    # FreeRADIUS requires a Message-Authenticator from 127.0.0.2
    client = Client(server=SERVER, secret=SECRET, dict=dictionary,
                    retries=1, timeout=2, enforce_ma=True)
    client.bind((STRICT_CLIENT, 0))
    reply = client.SendPacket(auth_request(client, "alice", "alice-password"))
    assert reply.code == packet.AccessAccept

    with pytest.raises(Timeout):
        client.SendPacket(auth_request(client, "alice", "alice-password",
                                       message_authenticator=False))


def test_wrong_secret_is_dropped(dictionary):
    client = Client(server=SERVER, secret=b"wrong-secret", dict=dictionary,
                    retries=1, timeout=1)
    with pytest.raises(Timeout):
        client.SendPacket(auth_request(client, "alice", "alice-password"))


def test_tagged_attributes(client):
    reply = client.SendPacket(auth_request(client, "tunnel", "tunnel-password"))
    assert reply.code == packet.AccessAccept
    assert reply["Tunnel-Type"] == ["VLAN", "L2TP"]
    assert reply["Tunnel-Type:1"] == ["VLAN"]
    assert reply["Tunnel-Medium-Type:1"] == ["IEEE-802"]
    assert reply["Tunnel-Private-Group-Id:1"] == ["100"]
    assert reply["Tunnel-Type:2"] == ["L2TP"]
    assert reply["Tunnel-Medium-Type:2"] == ["IPv4"]
    assert reply["Tunnel-Server-Endpoint:2"] == ["192.0.2.1"]
    assert reply["Tunnel-Password:2"] == [
        "a-tunnel-password-longer-than-16-octets"]
    assert "Tunnel-Password:1" not in reply


def test_vendor_attributes(client):
    reply = client.SendPacket(auth_request(client, "vendor", "vendor-password"))
    assert reply.code == packet.AccessAccept
    assert reply["Cisco-AVPair"] == ["shell:priv-lvl=15", "ip:addr-pool=pyrad"]
    assert reply["MS-MPPE-Send-Key"] == [bytes(range(0, 32))]
    assert reply["MS-MPPE-Recv-Key"] == [bytes(range(32, 64))]


def test_reply_attribute_types(client):
    reply = client.SendPacket(auth_request(client, "types", "types-password"))
    assert reply.code == packet.AccessAccept
    assert reply["Service-Type"] == ["Framed-User"]
    assert reply["Framed-Protocol"] == ["PPP"]
    assert reply["Framed-IP-Netmask"] == ["255.255.255.0"]
    assert reply["Session-Timeout"] == [3600]
    assert reply["Idle-Timeout"] == [600]
    assert reply["Class"] == [b"\x01\x02\x03\x04\x05"]
    assert reply["Framed-IPv6-Prefix"] == ["2001:db8:1::/64"]
    assert reply["Delegated-IPv6-Prefix"] == ["2001:db8:2::/56"]


def test_request_attribute_types(client):
    # FreeRADIUS echoes the request attributes it decoded in Reply-Message
    timestamp = int(time.time())
    req = auth_request(
        client, "echo", "echo-password",
        NAS_IP_Address="192.0.2.10",
        NAS_IPv6_Address=socket.inet_pton(socket.AF_INET6, "2001:db8::10"),
        NAS_Port=4711,
        Service_Type="Framed-User",
        Framed_IPv6_Prefix="2001:db8:3::/48",
        Event_Timestamp=timestamp,
        Cisco_AVPair="request:avpair=1")
    req.AddAttribute("Tunnel-Type:1", "VLAN")
    req.AddAttribute("Tunnel-Private-Group-Id:1", "100")
    req.AddAttribute("Tunnel-Private-Group-Id:2", "200")
    reply = client.SendPacket(req)
    assert reply.code == packet.AccessAccept
    assert reply["Reply-Message"] == [
        f"192.0.2.10 2001:db8::10 4711 Framed-User 2001:db8:3::/48 "
        f"{timestamp} VLAN 100 200 request:avpair=1"]


def test_ipv6(dictionary):
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is not available")
    client = Client(server="::1", secret=SECRET, dict=dictionary,
                    retries=2, timeout=2, enforce_ma=True)
    reply = client.SendPacket(auth_request(client, "alice", "alice-password"))
    assert reply.code == packet.AccessAccept
    assert reply["Reply-Message"] == ["Hello, alice"]


def test_status_server(client):
    req = client.CreateAuthPacket(code=packet.StatusServer)
    reply = client.SendPacket(req)
    assert reply.code == packet.AccessAccept


def test_status_server_with_enforce_ma(dictionary):
    client = Client(server=SERVER, secret=SECRET, dict=dictionary,
                    retries=2, timeout=2, enforce_ma=True)
    reply = client.SendPacket(client.CreateAuthPacket(code=packet.StatusServer))
    assert reply.code == packet.AccessAccept
    assert "Message-Authenticator" in reply


@pytest.mark.parametrize("status", ["Start", "Interim-Update", "Stop"])
def test_accounting(client, status):
    req = client.CreateAcctPacket(User_Name="alice")
    req["Acct-Status-Type"] = status
    req["Acct-Session-Id"] = "pyrad-integration"
    req["NAS-Identifier"] = "pyrad"
    req["Framed-IP-Address"] = "10.0.0.1"
    reply = client.SendPacket(req)
    assert reply.code == packet.AccountingResponse


def test_accounting_attributes(client):
    req = client.CreateAcctPacket(User_Name="alice")
    req["Acct-Status-Type"] = "Stop"
    req["Acct-Session-Id"] = "pyrad-integration-attributes"
    req["Acct-Session-Time"] = 3600
    req["Acct-Input-Octets"] = 2**32 - 1
    req["Acct-Terminate-Cause"] = "User-Request"
    req["Event-Timestamp"] = int(time.time())
    req["Framed-IPv6-Prefix"] = "2001:db8:1::/64"
    req.AddAttribute("Tunnel-Type:1", "VLAN")
    req.AddAttribute("Tunnel-Private-Group-Id:1", "100")
    req["Cisco-AVPair"] = ["acct:first=1", "acct:second=2"]
    reply = client.SendPacket(req)
    assert reply.code == packet.AccountingResponse


def test_accounting_wrong_secret_is_dropped(dictionary):
    client = Client(server=SERVER, secret=b"wrong-secret", dict=dictionary,
                    retries=1, timeout=1)
    req = client.CreateAcctPacket(User_Name="alice")
    req["Acct-Status-Type"] = "Start"
    req["Acct-Session-Id"] = "pyrad-integration-wrong-secret"
    with pytest.raises(Timeout):
        client.SendPacket(req)


def test_async_client(dictionary):
    async def run():
        client = ClientAsync(server=SERVER, secret=SECRET, dict=dictionary,
                             loop=asyncio.get_running_loop(), timeout=2)
        await client.initialize_transports(enable_auth=True, enable_acct=True)
        try:
            auth = await client.SendPacket(
                auth_request(client, "alice", "alice-password"))
            acct_req = client.CreateAcctPacket(User_Name="alice")
            acct_req["Acct-Status-Type"] = "Start"
            acct_req["Acct-Session-Id"] = "pyrad-integration-async"
            acct = await client.SendPacket(acct_req)
        finally:
            await client.deinitialize_transports()
        return auth, acct

    auth, acct = asyncio.run(run())
    assert auth.code == packet.AccessAccept
    assert auth["Reply-Message"] == ["Hello, alice"]
    assert acct.code == packet.AccountingResponse


def test_async_client_attributes(dictionary):
    async def run():
        client = ClientAsync(server=SERVER, secret=SECRET, dict=dictionary,
                             loop=asyncio.get_running_loop(), timeout=2,
                             enforce_ma=True)
        await client.initialize_transports(enable_auth=True)
        try:
            return (
                await client.SendPacket(chap_request(client, "alice", "alice-password")),
                await client.SendPacket(auth_request(client, "alice", "wrong")),
                await client.SendPacket(auth_request(client, "tunnel", "tunnel-password")),
                await client.SendPacket(auth_request(client, "vendor", "vendor-password")),
                await client.SendPacket(client.CreateAuthPacket(code=packet.StatusServer)),
            )
        finally:
            await client.deinitialize_transports()

    chap, reject, tunnel, vendor, status = asyncio.run(run())
    assert chap.code == packet.AccessAccept
    assert reject.code == packet.AccessReject
    assert tunnel.code == packet.AccessAccept
    assert tunnel["Tunnel-Private-Group-Id:1"] == ["100"]
    # salt encrypted attributes use the request authenticator of the reply
    assert tunnel["Tunnel-Password:2"] == [
        "a-tunnel-password-longer-than-16-octets"]
    assert vendor["MS-MPPE-Send-Key"] == [bytes(range(0, 32))]
    assert status.code == packet.AccessAccept
