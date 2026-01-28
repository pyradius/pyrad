# tools.py
#
# Utility functions
import binascii
import ipaddress
import struct
import six


# -------------------------
# Encoding helpers
# -------------------------

def EncodeString(value):
    """
    Encode a RADIUS 'string' value to bytes (UTF-8).
    Accepts: str -> bytes, bytes -> bytes
    """
    if value is None:
        return b""
    if isinstance(value, bytes):
        if len(value) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return value
    if isinstance(value, six.text_type):
        if len(value) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return value.encode("utf-8")
    raise TypeError("Can only encode str/bytes as string")


def EncodeOctets(value):
    """
    Encodes RADIUS attributes of type "octets" into a byte sequence.

    Supported inputs:
    - bytes / bytearray:
        * If the value starts with b"0x", it is treated as a hex string and decoded.
        * Otherwise the byte value is passed through unchanged.
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
        if b.startswith(b"0x"):
            out = binascii.unhexlify(b[2:])
        else:
            out = b

        if len(out) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")
        return out

    if isinstance(value, six.text_type):
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
    Encode a RADIUS 'ipaddr' value.
    Traditionally IPv4, but accept IPv6 as well (robust for real-world use).
    """
    if not isinstance(addr, six.string_types):
        raise TypeError("Address has to be a string")
    return ipaddress.ip_address(addr).packed


def EncodeIPv6Address(addr):
    """
    Encode a RADIUS 'ipv6addr' value to 16 bytes.
    Accepts: str, IPv6Address
    """
    if isinstance(addr, ipaddress.IPv6Address):
        return addr.packed
    if not isinstance(addr, six.string_types):
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
    if isinstance(value, six.string_types):
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
        # netaddr.IPNetwork uses .ip and .prefixlen
        return struct.pack("2B", 0, int(value.prefixlen)) + value.ip.packed

    else:
        raise TypeError("IPv6 Prefix has to be a string, IPv6Network, IPv6Address, or netaddr IPNetwork")

    if getattr(net, "version", None) != 6:
        raise ValueError("not an IPv6 prefix")

    return struct.pack("2B", 0, net.prefixlen) + net.network_address.packed


def EncodeAscendBinary(orig_str):
    """
    Ascend binary format encoder.
    """
    terms = {
        "family":    b"\x01",
        "action":    b"\x00",
        "direction": b"\x01",
        "src":       b"\x00\x00\x00\x00",
        "dst":       b"\x00\x00\x00\x00",
        "srcl":      b"\x00",
        "dstl":      b"\x00",
        "proto":     b"\x00",
        "sport":     b"\x00\x00",
        "dport":     b"\x00\x00",
        "sportq":    b"\x00",
        "dportq":    b"\x00",
    }

    family = "ipv4"
    for t in orig_str.split(" "):
        key, value = t.split("=")
        if key == "family" and value == "ipv6":
            family = "ipv6"
            terms[key] = b"\x03"
            if terms["src"] == b"\x00\x00\x00\x00":
                terms["src"] = 16 * b"\x00"
            if terms["dst"] == b"\x00\x00\x00\x00":
                terms["dst"] = 16 * b"\x00"
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

    trailer = 8 * b"\x00"
    return b"".join((
        terms["family"], terms["action"], terms["direction"], b"\x00",
        terms["src"], terms["dst"], terms["srcl"], terms["dstl"],
        terms["proto"], b"\x00", terms["sport"], terms["dport"],
        terms["sportq"], terms["dportq"], b"\x00\x00", trailer
    ))


def EncodeInteger(num, format="!I"):
    try:
        num = int(num)
    except Exception:
        raise TypeError("Can not encode non-integer as integer")
    return struct.pack(format, num)


def EncodeInteger64(num, format="!Q"):
    try:
        num = int(num)
    except Exception:
        raise TypeError("Can not encode non-integer as integer64")
    return struct.pack(format, num)


def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError("Can not encode non-integer as date")
    return struct.pack("!I", num)


# -------------------------
# Decoding helpers
# -------------------------

def DecodeString(value):
    # Be tolerant: bytes -> utf-8 (replace), else passthrough
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def DecodeOctets(value):
    return value


def DecodeAddress(addr):
    return str(ipaddress.ip_address(addr))


def DecodeIPv6Prefix(addr):
    # RADIUS IPv6-Prefix is: 2 bytes (reserved, prefixlen) + prefix bytes (0..16)
    addr = addr + b"\x00" * (18 - len(addr))
    _, length = struct.unpack("!BB", addr[:2])
    prefix_bytes = addr[2:18]
    prefix = ipaddress.IPv6Address(prefix_bytes)
    return str(ipaddress.IPv6Network((prefix, int(length)), strict=False))


def DecodeIPv6Address(addr):
    addr = addr + b"\x00" * (16 - len(addr))
    return str(ipaddress.IPv6Address(addr))


def DecodeAscendBinary(value):
    return value


def DecodeInteger(num, format="!I"):
    return struct.unpack(format, num)[0]


def DecodeInteger64(num, format="!Q"):
    return struct.unpack(format, num)[0]


def DecodeDate(num):
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
    else:
        raise ValueError("Unknown attribute type %s" % datatype)
