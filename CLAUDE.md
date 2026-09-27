# CLAUDE.md

pyrad is a RADIUS client/server library (RFC 2865 and related RFCs), published
on PyPI. It is a mature library with long-standing public API users, so keep
changes backwards compatible.

## Commands

The project uses uv (as CI does):

```sh
uv sync --all-groups --dev        # install dependencies
uv run ruff check .               # lint
uv run pytest                     # unit tests (pyrad/tests only)
uv run coverage run -m pytest && uv run coverage report -m
```

Integration tests run against a real FreeRADIUS server in docker and are not
part of a plain `pytest` run:

```sh
docker run -d --name freeradius --network host \
  -v "$PWD/tests/integration/freeradius/clients.conf:/opt/etc/raddb/clients.conf:ro" \
  -v "$PWD/tests/integration/freeradius/authorize:/opt/etc/raddb/mods-config/files/authorize:ro" \
  freeradius/freeradius-server:latest-3.2-alpine -X
FREERADIUS_CONTAINER=freeradius uv run pytest tests/integration
```

## Layout

- `pyrad/packet.py`: packet encoding/decoding, password encryption,
  Message-Authenticator
- `pyrad/client.py`, `pyrad/server.py`, `pyrad/proxy.py`: blocking
  client/server built on `pyrad/host.py`
- `pyrad/client_async.py`, `pyrad/server_async.py`: asyncio client/server
- `pyrad/dictionary.py`, `pyrad/dictfile.py`: FreeRADIUS-style dictionary parser
- `pyrad/tools.py`: attribute value encoding/decoding per data type
- `pyrad/curved.py`: Twisted integration (Twisted is not a dependency; the
  tests stub it)
- `pyrad/tests/`: unit tests (unittest style, run with pytest), test
  dictionaries in `pyrad/tests/data/`
- `tests/integration/`: FreeRADIUS integration tests

## Conventions

- Keep the existing public API names (`CreateAuthPacket`, `SendPacket`,
  `PwCrypt`, ...) even though they are not PEP 8; don't rename them.
- Secrets are `bytes`. Attribute values of undefined attributes are raw
  `bytes` keyed by the integer attribute code, or by `(vendor, code)`.
- Python 3.10+ is supported (`requires-python`, the CI matrix and the
  classifiers must stay in sync). Don't use syntax or stdlib features newer
  than 3.10 in `pyrad/`.
- The ruff rule set is pinned in `pyproject.toml`; don't widen it as part of
  unrelated changes.
- Tests: `unittest.TestCase` classes with `testCamelCase` method names. Async
  tests bind to free loopback ports (see `free_ports` in
  `pyrad/tests/test_async.py`), never fixed ports.
- Security-relevant behavior (Message-Authenticator / BlastRADIUS,
  CVE-2024-3596) must stay covered by `pyrad/tests/test_blastradius.py`.

## Commits and changelog

- Commit subjects use a type prefix: `fix:`, `test:`, `ci:`, `docs:`,
  followed by a short imperative summary.
- User-visible changes get an entry in the `Unreleased` section of
  `CHANGES.rst`.
