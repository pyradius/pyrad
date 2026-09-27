# tools.py
#
# Utility functions
import binascii
import ipaddress
import re
import struct

_IFID_RE = re.compile(r"([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):"
                      r"([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})")
_ETHER_RE = re.compile(r"([0-9a-fA-F]{1,2})([:-])([0-9a-fA-F]{1,2})\2"
                       r"([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})\2"
                       r"([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})")


# -------------------------
# Encoding helpers
# -------------------------

def EncodeString(value):
    """
    Encode a RADIUS 'string' value to bytes (UTF-8).
    Accepts: str -> bytes, bytes -> bytes
    The encoded value must not be longer than 253 octets.
    """
    if value is None:
        return b""
    if isinstance(value, bytes):
        if len(value) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return value
    if isinstance(value, str):
        # the limit applies to the encoded value: a non-ASCII character
        # takes more than one octet in UTF-8
        encoded = value.encode("utf-8")
        if len(encoded) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return encoded
    raise TypeError("Can only encode str/bytes as string")


def EncodeOctets(value):
    """
    Encodes RADIUS attributes of type "octets" into a byte sequence.

    Supported inputs:
    - bytes / bytearray:
        * If the value starts with b"0x" followed by valid hex digits, it is
          treated as a hex string and decoded.
        * Otherwise the byte value is passed through unchanged, so binary
          values which happen to start with b"0x" (e.g. a CHAP-Password)
          are not modified.
    - str:
        * "0x..."  → hexadecimal representation, decoded into bytes
        * Decimal string (e.g. "65"):
            - 0..255 → encoded as a single byte
            - >255   → encoded as a minimal big-endian byte sequence
        * Any other string is UTF-8 encoded

    Constraints:
    - The resulting byte sequence must not exceed 253 bytes
      (RADIUS attribute size limit).

    This behavior preserves compatibility with legacy pyrad dictionary
    definitions and existing test cases.
    """
    if value is None:
        return b""

    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        out = b
        if b.startswith(b"0x"):
            try:
                out = binascii.unhexlify(b[2:])
            except binascii.Error:
                pass

        if len(out) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return out

    if isinstance(value, str):
        s = value
        if s.startswith("0x"):
            out = binascii.unhexlify(s[2:])
        elif s.isdecimal():
            n = int(s)
            if n < 0:
                raise ValueError("Octet decimal value must be >= 0")
            if n <= 255:
                out = struct.pack("!B", n)
            else:
                byte_len = (n.bit_length() + 7) // 8
                out = n.to_bytes(byte_len, "big")
        else:
            out = s.encode("utf-8")

        if len(out) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return out

    raise TypeError("Can only encode str/bytes as octets")


def EncodeAddress(addr):
    """
    Encode a RADIUS 'ipaddr' value, an IPv4 address of four octets
    (RFC 8044 section 3.8). IPv6 addresses raise a ValueError, use the
    'ipv6addr' type for them.
    """
    if not isinstance(addr, str):
        raise TypeError("Address has to be a string")
    return ipaddress.IPv4Address(addr).packed


def EncodeIPv6Address(addr):
    """
    Encode a RADIUS 'ipv6addr' value to 16 bytes.
    Accepts: str, IPv6Address
    """
    if isinstance(addr, ipaddress.IPv6Address):
        return addr.packed
    if not isinstance(addr, str):
        raise TypeError("IPv6 Address has to be a string")
    return ipaddress.IPv6Address(addr).packed


def EncodeIPv6Prefix(value, default_prefixlen=128):
    """
    Encode a RADIUS 'ipv6prefix' value.

    Accepts:
      - "2001:db8::/64" (str)
      - "2001:db8::"    (str) -> uses default_prefixlen
      - ipaddress.IPv6Network
      - ipaddress.IPv6Address -> uses default_prefixlen
      - netaddr.IPNetwork (duck-typed via .ip/.prefixlen)
    """
    # 1) string input
    if isinstance(value, str):
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
        else:
            addr = ipaddress.IPv6Address(value)
            net = ipaddress.IPv6Network((addr, default_prefixlen), strict=False)

    # 2) stdlib ipaddress objects
    elif isinstance(value, ipaddress.IPv6Network):
        net = value
    elif isinstance(value, ipaddress.IPv6Address):
        net = ipaddress.IPv6Network((value, default_prefixlen), strict=False)

    # 3) netaddr fallback (duck typing)
    elif hasattr(value, "ip") and hasattr(value, "prefixlen"):
        # netaddr.IPNetwork uses .ip and .prefixlen; convert it so that the
        # IP version is checked and the host bits are cleared like for str
        net = ipaddress.ip_network(
            "%s/%d" % (value.ip, int(value.prefixlen)), strict=False)

    else:
        raise TypeError("IPv6 Prefix has to be a string, IPv6Network, IPv6Address, or netaddr IPNetwork")

    if getattr(net, "version", None) != 6:
        raise ValueError("not an IPv6 prefix")

    return struct.pack("2B", 0, net.prefixlen) + net.network_address.packed


def EncodeAscendBinary(orig_str):
    """
    Ascend binary format encoder.

    The value is a whitespace separated list of key=value terms. The
    src and dst addresses have to match the family (ipv4 by default,
    or family=ipv6), otherwise a ValueError is raised.
    """
    terms = {
        "family":    b"\x01",
        "action":    b"\x00",
        "direction": b"\x01",
        "src":       None,
        "dst":       None,
        "srcl":      b"\x00",
        "dstl":      b"\x00",
        "proto":     b"\x00",
        "sport":     b"\x00\x00",
        "dport":     b"\x00\x00",
        "sportq":    b"\x00",
        "dportq":    b"\x00",
    }

    if orig_str.strip() == "delete":
        return 8 * b"\x00"

    for t in orig_str.split():
        key, value = t.split("=")
        if key == "family" and value == "ipv6":
            terms[key] = b"\x03"
        elif key == "action" and value == "accept":
            terms[key] = b"\x01"
        elif key == "action" and value == "redirect":
            terms[key] = b"\x20"
        elif key == "direction" and value == "out":
            terms[key] = b"\x00"
        elif key in ("src", "dst"):
            net = ipaddress.ip_network(value, strict=False)
            terms[key] = net.network_address.packed
            terms[key + "l"] = struct.pack("B", net.prefixlen)
        elif key in ("sport", "dport"):
            terms[key] = struct.pack("!H", int(value))
        elif key in ("sportq", "dportq", "proto"):
            terms[key] = struct.pack("B", int(value))

    # the addresses have to match the family, which may be given after them
    addrlen = 16 if terms["family"] == b"\x03" else 4
    for key in ("src", "dst"):
        if terms[key] is None:
            terms[key] = addrlen * b"\x00"
        elif len(terms[key]) != addrlen:
            raise ValueError("%s address does not match the filter family %s"
                             % (key, "ipv6" if addrlen == 16 else "ipv4"))

    trailer = 8 * b"\x00"
    return b"".join((
        terms["family"], terms["action"], terms["direction"], b"\x00",
        terms["src"], terms["dst"], terms["srcl"], terms["dstl"],
        terms["proto"], b"\x00", terms["sport"], terms["dport"],
        terms["sportq"], terms["dportq"], b"\x00\x00", trailer
    ))


def _PackInteger(num, format, datatype):
    """Pack an integer, raising a ValueError if it is out of range."""
    bits = 8 * struct.calcsize(format)
    if format[-1].islower():
        low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    else:
        low, high = 0, (1 << bits) - 1
    if not low <= num <= high:
        raise ValueError("%s value %d out of range (%d..%d)"
                         % (datatype, num, low, high))
    return struct.pack(format, num)


def EncodeIfId(value):
    """
    Encode a RADIUS 'ifid' value, an IPv6 interface identifier of eight
    octets (RFC 3162 section 2.2).

    Accepts the textual form FreeRADIUS uses, four colon separated groups
    of one to four hex digits (e.g. "211:22ff:fe33:4455"), or bytes of
    length 8.
    """
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        _CheckLength(value, 8, "ifid")
        return value
    if not isinstance(value, str):
        raise TypeError("Interface id has to be a string or bytes")
    match = _IFID_RE.fullmatch(value)
    if match is None:
        raise ValueError("Invalid ifid value: %r" % value)
    return struct.pack("!4H", *(int(group, 16) for group in match.groups()))


def EncodeEther(value):
    """
    Encode a RADIUS 'ether' value, an Ethernet MAC address of six octets.

    Accepts six groups of one or two hex digits, separated by colons or
    dashes (e.g. "00:11:22:aa:bb:cc" or "00-11-22-AA-BB-CC"), or bytes of
    length 6.
    """
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        _CheckLength(value, 6, "ether")
        return value
    if not isinstance(value, str):
        raise TypeError("Ethernet address has to be a string or bytes")
    match = _ETHER_RE.fullmatch(value)
    if match is None:
        raise ValueError("Invalid ether value: %r" % value)
    groups = match.groups()
    return bytes(int(group, 16) for group in groups[:1] + groups[2:])


def EncodeInteger(num, format="!I"):
    try:
        num = int(num)
    except Exception:
        raise TypeError("Can not encode non-integer as integer")
    return _PackInteger(num, format, "integer")


def EncodeInteger64(num, format="!Q"):
    try:
        num = int(num)
    except Exception:
        raise TypeError("Can not encode non-integer as integer64")
    return _PackInteger(num, format, "integer64")


def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError("Can not encode non-integer as date")
    return _PackInteger(num, "!I", "date")


# -------------------------
# Decoding helpers
# -------------------------

def DecodeString(value):
    # Values which are not valid UTF-8 (e.g. an encrypted User-Password)
    # are returned as bytes so no data is lost.
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value
    return value


def DecodeOctets(value):
    return value


def _CheckLength(value, length, datatype):
    if len(value) != length:
        raise ValueError("Invalid %s value: expected %d bytes, got %d"
                         % (datatype, length, len(value)))


def DecodeAddress(addr):
    _CheckLength(addr, 4, "ipaddr")
    return str(ipaddress.ip_address(addr))


def DecodeIPv6Prefix(addr):
    # RADIUS IPv6-Prefix is: 2 bytes (reserved, prefixlen) + prefix bytes (0..16)
    if not 2 <= len(addr) <= 18:
        raise ValueError("Invalid ipv6prefix value: expected 2 to 18 bytes, got %d"
                         % len(addr))
    addr = addr + b"\x00" * (18 - len(addr))
    _, length = struct.unpack("!BB", addr[:2])
    prefix_bytes = addr[2:18]
    prefix = ipaddress.IPv6Address(prefix_bytes)
    return str(ipaddress.IPv6Network((prefix, int(length)), strict=False))


def DecodeIPv6Address(addr):
    if len(addr) > 16:
        raise ValueError("Invalid ipv6addr value: expected at most 16 bytes, got %d"
                         % len(addr))
    addr = addr + b"\x00" * (16 - len(addr))
    return str(ipaddress.IPv6Address(addr))


def DecodeIfId(value):
    # printed like FreeRADIUS does, e.g. "211:22ff:fe33:4455"
    _CheckLength(value, 8, "ifid")
    return "%x:%x:%x:%x" % struct.unpack("!4H", value)


def DecodeEther(value):
    _CheckLength(value, 6, "ether")
    return ":".join("%02x" % octet for octet in value)


def DecodeAscendBinary(value):
    return value


def DecodeInteger(num, format="!I"):
    _CheckLength(num, struct.calcsize(format), "integer")
    return struct.unpack(format, num)[0]


def DecodeInteger64(num, format="!Q"):
    _CheckLength(num, struct.calcsize(format), "integer64")
    return struct.unpack(format, num)[0]


def DecodeDate(num):
    _CheckLength(num, 4, "date")
    return struct.unpack("!I", num)[0]


# -------------------------
# Attribute encode/decode dispatch
# -------------------------

def EncodeAttr(datatype, value):
    if datatype == "string":
        return EncodeString(value)
    elif datatype == "octets":
        return EncodeOctets(value)
    elif datatype == "integer":
        return EncodeInteger(value)
    elif datatype == "ipaddr":
        return EncodeAddress(value)
    elif datatype == "ipv6prefix":
        return EncodeIPv6Prefix(value)
    elif datatype == "ipv6addr":
        return EncodeIPv6Address(value)
    elif datatype == "abinary":
        return EncodeAscendBinary(value)
    elif datatype == "signed":
        return EncodeInteger(value, "!i")
    elif datatype == "short":
        return EncodeInteger(value, "!H")
    elif datatype == "byte":
        return EncodeInteger(value, "!B")
    elif datatype == "date":
        return EncodeDate(value)
    elif datatype == "integer64":
        return EncodeInteger64(value)
    elif datatype == "ifid":
        return EncodeIfId(value)
    elif datatype == "ether":
        return EncodeEther(value)
    else:
        raise ValueError("Unknown attribute type %s" % datatype)


def DecodeAttr(datatype, value):
    if datatype == "string":
        return DecodeString(value)
    elif datatype == "octets":
        return DecodeOctets(value)
    elif datatype == "integer":
        return DecodeInteger(value)
    elif datatype == "ipaddr":
        return DecodeAddress(value)
    elif datatype == "ipv6prefix":
        return DecodeIPv6Prefix(value)
    elif datatype == "ipv6addr":
        return DecodeIPv6Address(value)
    elif datatype == "abinary":
        return DecodeAscendBinary(value)
    elif datatype == "signed":
        return DecodeInteger(value, "!i")
    elif datatype == "short":
        return DecodeInteger(value, "!H")
    elif datatype == "byte":
        return DecodeInteger(value, "!B")
    elif datatype == "date":
        return DecodeDate(value)
    elif datatype == "integer64":
        return DecodeInteger64(value)
    elif datatype == "ifid":
        return DecodeIfId(value)
    elif datatype == "ether":
        return DecodeEther(value)
    else:
        raise ValueError("Unknown attribute type %s" % datatype)
