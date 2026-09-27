"""Integration tests for the pyrad servers using FreeRADIUS radclient.

radclient runs in the FreeRADIUS docker container (host network). Access
requests are sent with ``-b``, which enables its BlastRADIUS checks: the
reply must contain a Message-Authenticator and must echo the Proxy-State
attributes exactly. radclient decodes the reply attributes, which verifies
the encoding of the pyrad servers.
"""
import asyncio
import re
import socket
import subprocess
import threading

import pytest

from pyrad import packet
from pyrad.server import RemoteHost, Server
from pyrad.server_async import ServerAsync

from .conftest import CONTAINER, SECRET, SERVER

pytestmark = pytest.mark.skipif(
    not CONTAINER, reason="FREERADIUS_CONTAINER is not set")

PASSWORD = "alice-password"
TUNNEL_PASSWORD = "a-tunnel-password-longer-than-16-octets"
SEND_KEY = bytes(range(0, 32))


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


# auth, acct and coa ports of the blocking server, the asyncio server and
# the blocking server enforcing Message-Authenticator
(SYNC_AUTH, SYNC_ACCT, SYNC_COA, ASYNC_AUTH, ASYNC_ACCT, ASYNC_COA,
 STRICT_AUTH_PORT) = free_ports(7)
PORTS = {
    "sync": {"auth": SYNC_AUTH, "acct": SYNC_ACCT, "coa": SYNC_COA},
    "async": {"auth": ASYNC_AUTH, "acct": ASYNC_ACCT, "coa": ASYNC_COA},
}


def create_reply(create_reply_packet, pkt):
    """Return the reply of both servers to a request."""
    if pkt.code == packet.AccessRequest:
        accept = (pkt["User-Name"] == ["alice"]
                  and pkt.PwDecrypt(pkt[2][0]) == PASSWORD)
        reply = create_reply_packet(pkt, Reply_Message="Hello, alice")
        reply.code = packet.AccessAccept if accept else packet.AccessReject
        if accept:
            reply.AddAttribute("Tunnel-Type:1", "VLAN")
            reply.AddAttribute("Tunnel-Medium-Type:1", "IEEE-802")
            reply.AddAttribute("Tunnel-Private-Group-Id:1", "100")
            reply.AddAttribute("Tunnel-Password:2", TUNNEL_PASSWORD)
            reply["Cisco-AVPair"] = ["shell:priv-lvl=15", "ip:addr-pool=pyrad"]
            reply["MS-MPPE-Send-Key"] = SEND_KEY
            reply["Session-Timeout"] = 3600
            reply["Framed-IPv6-Prefix"] = "2001:db8:1::/64"
        return reply
    reply = create_reply_packet(pkt)
    if pkt.code == packet.DisconnectRequest:
        reply.code = packet.DisconnectACK
    return reply


class PyradServer(Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = []

    def handle(self, pkt):
        self.received.append(pkt)
        self.SendReplyPacket(pkt.fd, create_reply(self.CreateReplyPacket, pkt))

    HandleAuthPacket = HandleAcctPacket = handle
    HandleCoaPacket = HandleDisconnectPacket = handle


class AsyncPyradServer(ServerAsync):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = []

    def handle(self, protocol, pkt, addr):
        self.received.append(pkt)
        protocol.send_response(create_reply(self.CreateReplyPacket, pkt), addr)

    handle_auth_packet = handle_acct_packet = handle
    handle_coa_packet = handle_disconnect_packet = handle


@pytest.fixture(scope="module")
def pyrad_servers(dictionary):
    """Run a blocking server, a blocking server enforcing
    Message-Authenticator and an asyncio server."""
    hosts = {SERVER: RemoteHost(SERVER, SECRET, "radclient")}
    servers = {
        "sync": PyradServer(
            addresses=[SERVER], authport=SYNC_AUTH, acctport=SYNC_ACCT,
            coaport=SYNC_COA, hosts=hosts, dict=dictionary, coa_enabled=True),
        "strict": PyradServer(
            addresses=[SERVER], authport=STRICT_AUTH_PORT, hosts=hosts,
            dict=dictionary, acct_enabled=False, enforce_ma=True),
    }
    for server in servers.values():
        threading.Thread(target=server.Run, daemon=True).start()

    loop = asyncio.new_event_loop()
    servers["async"] = AsyncPyradServer(
        auth_port=ASYNC_AUTH, acct_port=ASYNC_ACCT, coa_port=ASYNC_COA,
        hosts=hosts, dictionary=dictionary, loop=loop)
    loop.run_until_complete(servers["async"].initialize_transports(
        enable_auth=True, enable_acct=True, enable_coa=True, addresses=[SERVER]))
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    yield servers

    loop.call_soon_threadsafe(loop.stop)
    thread.join()
    loop.run_until_complete(servers["async"].deinitialize_transports())
    loop.close()
    for server in (servers["sync"], servers["strict"]):
        for fd in server.authfds + server.acctfds + server.coafds:
            fd.close()


@pytest.fixture(params=["sync", "async"])
def server(request, pyrad_servers):
    """The blocking and the asyncio server with their ports."""
    return pyrad_servers[request.param], PORTS[request.param]


def radclient(attributes, port, command="auth", secret=SECRET):
    """Send a request with radclient and return (exit code, output)."""
    args = ["-b"] if command == "auth" else []
    result = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "/opt/bin/radclient", *args, "-x",
         "-r", "1", "-t", "2", f"{SERVER}:{port}", command, secret.decode()],
        input="\n".join(attributes) + "\n", capture_output=True, text=True,
        timeout=30)
    return result.returncode, result.stdout + result.stderr


def assert_attribute(output, line):
    """Assert radclient printed the received attribute line."""
    assert re.search(r"^\s*" + re.escape(line) + r"\s*$", output, re.MULTILINE), output


def test_accept(server):
    _, ports = server
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}"], ports["auth"])
    assert code == 0, output
    assert "Received Access-Accept" in output
    assert "Hello, alice" in output


def test_reject(server):
    _, ports = server
    code, output = radclient(
        ["User-Name = alice", "User-Password = wrong"], ports["auth"])
    assert code != 0, output
    assert "Received Access-Reject" in output


def test_reply_attributes(server):
    # radclient decodes the attributes encoded by pyrad
    _, ports = server
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}"], ports["auth"])
    assert code == 0, output
    assert_attribute(output, "Tunnel-Type:1 = VLAN")
    assert_attribute(output, "Tunnel-Medium-Type:1 = IEEE-802")
    assert_attribute(output, 'Tunnel-Private-Group-Id:1 = "100"')
    assert_attribute(output, f'Tunnel-Password:2 = "{TUNNEL_PASSWORD}"')
    assert_attribute(output, 'Cisco-AVPair = "shell:priv-lvl=15"')
    assert_attribute(output, 'Cisco-AVPair = "ip:addr-pool=pyrad"')
    assert_attribute(output, f"MS-MPPE-Send-Key = 0x{SEND_KEY.hex()}")
    assert_attribute(output, "Session-Timeout = 3600")
    assert_attribute(output, "Framed-IPv6-Prefix = 2001:db8:1::/64")


def test_request_attributes(server):
    # pyrad decodes the attributes encoded by radclient
    srv, ports = server
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}",
        "Tunnel-Type:1 = VLAN", 'Tunnel-Private-Group-Id:1 = "100"',
        'Tunnel-Private-Group-Id:2 = "200"', 'Cisco-AVPair = "request:avpair=1"',
        "NAS-Port = 4711", "Framed-IPv6-Prefix = 2001:db8:3::/48"], ports["auth"])
    assert code == 0, output
    req = srv.received[-1]
    assert req["Tunnel-Type:1"] == ["VLAN"]
    assert req["Tunnel-Private-Group-Id"] == ["100", "200"]
    assert req["Tunnel-Private-Group-Id:2"] == ["200"]
    assert req["Cisco-AVPair"] == ["request:avpair=1"]
    assert req["NAS-Port"] == [4711]
    assert req["Framed-IPv6-Prefix"] == ["2001:db8:3::/48"]


def test_proxy_state_is_echoed(server):
    _, ports = server
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}",
        "Proxy-State = 0x01020304", "Proxy-State = 0x05060708"], ports["auth"])
    assert code == 0, output
    assert "Received Access-Accept" in output


def test_accounting(server):
    srv, ports = server
    code, output = radclient([
        "User-Name = alice", "Acct-Status-Type = Start",
        'Acct-Session-Id = "pyrad-radclient"'], ports["acct"], command="acct")
    assert code == 0, output
    assert "Received Accounting-Response" in output
    assert srv.received[-1]["Acct-Session-Id"] == ["pyrad-radclient"]


@pytest.mark.parametrize("command, request_code, reply", [
    ("coa", packet.CoARequest, "CoA-ACK"),
    ("disconnect", packet.DisconnectRequest, "Disconnect-ACK"),
])
def test_coa(server, command, request_code, reply):
    srv, ports = server
    code, output = radclient(["User-Name = alice"], ports["coa"], command=command)
    assert code == 0, output
    assert f"Received {reply}" in output
    assert srv.received[-1].code == request_code


@pytest.mark.parametrize("command, port, attributes", [
    ("auth", "auth", ["User-Name = alice", f"User-Password = {PASSWORD}"]),
    ("acct", "acct", ["User-Name = alice", "Acct-Status-Type = Start"]),
    ("coa", "coa", ["User-Name = alice"]),
    ("disconnect", "coa", ["User-Name = alice"]),
])
def test_wrong_secret_is_dropped(server, command, port, attributes):
    # the request authenticator of accounting, CoA and Disconnect requests
    # and the Message-Authenticator of Access-Requests use the secret
    srv, ports = server
    received = len(srv.received)
    code, output = radclient(attributes, ports[port], command=command,
                             secret=b"wrong-secret")
    assert code != 0, output
    assert "Received" not in output
    assert len(srv.received) == received


def test_enforce_message_authenticator(pyrad_servers):
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}"], STRICT_AUTH_PORT)
    assert code == 0, output

    # "!*" makes radclient send the request without Message-Authenticator
    code, output = radclient([
        "User-Name = alice", f"User-Password = {PASSWORD}",
        "Message-Authenticator !* ANY"], STRICT_AUTH_PORT)
    assert code != 0, output
    assert "Received Access-Accept" not in output
