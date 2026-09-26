"""Integration tests for the pyrad clients against FreeRADIUS.

Users and clients are configured in ``tests/integration/freeradius``.
pyrad adds a Message-Authenticator to all Access-Requests by default and
FreeRADIUS 3.2 adds one to all replies (BlastRADIUS countermeasures).
"""
import asyncio
import hashlib
import os

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


def test_status_server(client):
    req = client.CreateAuthPacket(code=packet.StatusServer)
    reply = client.SendPacket(req)
    assert reply.code == packet.AccessAccept


@pytest.mark.parametrize("status", ["Start", "Interim-Update", "Stop"])
def test_accounting(client, status):
    req = client.CreateAcctPacket(User_Name="alice")
    req["Acct-Status-Type"] = status
    req["Acct-Session-Id"] = "pyrad-integration"
    req["NAS-Identifier"] = "pyrad"
    req["Framed-IP-Address"] = "10.0.0.1"
    reply = client.SendPacket(req)
    assert reply.code == packet.AccountingResponse


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
