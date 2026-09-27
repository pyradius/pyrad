"""Fixtures for integration tests against a running FreeRADIUS server.

The server address and shared secret can be overridden with the
``RADIUS_SERVER`` and ``RADIUS_SECRET`` environment variables. The tests
of the pyrad server use radclient in the FreeRADIUS docker container named
by ``FREERADIUS_CONTAINER`` and are skipped if it is not set.
"""
import os
import time
from pathlib import Path

import pytest

from pyrad import packet
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary

DICTIONARY = Path(__file__).resolve().parent / "dictionary"

SERVER = os.environ.get("RADIUS_SERVER", "127.0.0.1")
SECRET = os.environ.get("RADIUS_SECRET", "testing123").encode()
STARTUP_TIMEOUT = float(os.environ.get("RADIUS_STARTUP_TIMEOUT", "30"))
# FreeRADIUS requires a Message-Authenticator from this client address
STRICT_CLIENT = "127.0.0.2"
CONTAINER = os.environ.get("FREERADIUS_CONTAINER")


@pytest.fixture(scope="session")
def dictionary():
    return Dictionary(str(DICTIONARY))


@pytest.fixture(scope="session", autouse=True)
def radius_server(dictionary):
    """Wait until the RADIUS server answers Status-Server requests."""
    client = Client(server=SERVER, secret=SECRET, dict=dictionary,
                    retries=1, timeout=1)
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while True:
        req = client.CreateAuthPacket(code=packet.StatusServer)
        try:
            client.SendPacket(req)
            return SERVER
        except (Timeout, OSError):
            if time.monotonic() > deadline:
                pytest.fail(f"RADIUS server {SERVER} did not answer "
                            f"within {STARTUP_TIMEOUT}s")
            time.sleep(1)


@pytest.fixture
def client(dictionary):
    return Client(server=SERVER, secret=SECRET, dict=dictionary,
                  retries=2, timeout=2)
