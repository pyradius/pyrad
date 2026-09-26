"""Integration tests for the pyrad server using FreeRADIUS radclient.

radclient runs in the FreeRADIUS docker container (host network) with
``-b``, which enables its BlastRADIUS checks: the reply must contain a
Message-Authenticator and must echo the Proxy-State attributes exactly.
"""
import socket
import subprocess
import threading

import pytest

from pyrad import packet
from pyrad.server import RemoteHost, Server

from .conftest import CONTAINER, SECRET, SERVER

pytestmark = pytest.mark.skipif(
    not CONTAINER, reason="FREERADIUS_CONTAINER is not set")

PASSWORD = "alice-password"


def free_ports(count):
    """Return distinct free UDP ports; FreeRADIUS shares the host network
    and uses ports like 18120 (inner-tunnel) itself."""
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind((SERVER, 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


AUTH_PORT, STRICT_AUTH_PORT = free_ports(2)


class PyradServer(Server):
    def HandleAuthPacket(self, pkt):
        accept = (pkt["User-Name"] == ["alice"]
                  and pkt.PwDecrypt(pkt[2][0]) == PASSWORD)
        reply = self.CreateReplyPacket(pkt, Reply_Message="Hello, alice")
        reply.code = packet.AccessAccept if accept else packet.AccessReject
        self.SendReplyPacket(pkt.fd, reply)


@pytest.fixture(scope="module", autouse=True)
def pyrad_servers(dictionary):
    """Run a default server and one enforcing Message-Authenticator."""
    hosts = {SERVER: RemoteHost(SERVER, SECRET, "radclient")}
    servers = [
        PyradServer(addresses=[SERVER], authport=AUTH_PORT, hosts=hosts,
                    dict=dictionary, acct_enabled=False),
        PyradServer(addresses=[SERVER], authport=STRICT_AUTH_PORT, hosts=hosts,
                    dict=dictionary, acct_enabled=False, enforce_ma=True),
    ]
    for server in servers:
        threading.Thread(target=server.Run, daemon=True).start()
    yield servers
    for server in servers:
        for fd in server.authfds:
            fd.close()


def radclient(attributes, port=AUTH_PORT):
    """Send an Access-Request with radclient and return (exit code, output)."""
    result = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "/opt/bin/radclient", "-b", "-x",
         "-r", "1", "-t", "2", f"{SERVER}:{port}", "auth", SECRET.decode()],
        input="\n".join(attributes) + "\n", capture_output=True, text=True,
        timeout=30)
    return result.returncode, result.stdout + result.stderr


def test_accept():
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}"])
    assert code == 0, output
    assert "Received Access-Accept" in output
    assert "Hello, alice" in output


def test_reject():
    code, output = radclient(["User-Name = alice", "User-Password = wrong"])
    assert code != 0, output
    assert "Received Access-Reject" in output


def test_proxy_state_is_echoed():
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}",
        "Proxy-State = 0x01020304", "Proxy-State = 0x05060708"])
    assert code == 0, output
    assert "Received Access-Accept" in output


def test_enforce_message_authenticator():
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}"],
        port=STRICT_AUTH_PORT)
    assert code == 0, output

    # "!*" makes radclient send the request without Message-Authenticator
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}",
        "Message-Authenticator !* ANY"], port=STRICT_AUTH_PORT)
    assert code != 0, output
    assert "Received Access-Accept" not in output
