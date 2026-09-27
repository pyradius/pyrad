import ipaddress

import netaddr

from pyrad import tools
import unittest


class EncodingTests(unittest.TestCase):
    def testStringEncoding(self):
        self.assertRaises(ValueError, tools.EncodeString, 'x' * 254)
        self.assertEqual(
                tools.EncodeString('1234567890'),
                b'1234567890')

    def testInvalidStringEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeString, 1)

    def testAddressEncoding(self):
        self.assertRaises((ValueError, Exception), tools.EncodeAddress, 'TEST123')
        self.assertEqual(
                tools.EncodeAddress('192.168.0.255'),
                b'\xc0\xa8\x00\xff')

    def testInvalidAddressEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeAddress, 1)

    def testIntegerEncoding(self):
        self.assertEqual(tools.EncodeInteger(0x01020304), b'\x01\x02\x03\x04')

    def testInteger64Encoding(self):
        self.assertEqual(
            tools.EncodeInteger64(0xFFFFFFFFFFFFFFFF), b'\xff' * 8
        )

    def testUnsignedIntegerEncoding(self):
        self.assertEqual(tools.EncodeInteger(0xFFFFFFFF), b'\xff\xff\xff\xff')

    def testInvalidIntegerEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeInteger, 'ONE')

    def testDateEncoding(self):
        self.assertEqual(tools.EncodeDate(0x01020304), b'\x01\x02\x03\x04')

    def testInvalidDataEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeDate, '1')

    def testEncodeAscendBinary(self):
        self.assertEqual(
            tools.EncodeAscendBinary('family=ipv4 action=discard direction=in dst=10.10.255.254/32'),
            b'\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testStringDecoding(self):
        self.assertEqual(
                tools.DecodeString(b'1234567890'),
                '1234567890')
        self.assertEqual(tools.DecodeString('é'.encode('utf-8')), 'é')

    def testStringDecodingOfStr(self):
        self.assertEqual(tools.DecodeString('1234567890'), '1234567890')

    def testStringDecodingInvalidUtf8ReturnsBytes(self):
        # e.g. an encrypted User-Password, which must not be modified
        self.assertEqual(tools.DecodeString(b'\xd3U;\xb2'), b'\xd3U;\xb2')

    def testAddressDecoding(self):
        self.assertEqual(
                tools.DecodeAddress(b'\xc0\xa8\x00\xff'),
                '192.168.0.255')

    def testIntegerDecoding(self):
        self.assertEqual(
                tools.DecodeInteger(b'\x01\x02\x03\x04'),
                0x01020304)

    def testInteger64Decoding(self):
        self.assertEqual(
            tools.DecodeInteger64(b'\xff' * 8), 0xFFFFFFFFFFFFFFFF
        )

    def testDateDecoding(self):
        self.assertEqual(
                tools.DecodeDate(b'\x01\x02\x03\x04'),
                0x01020304)

    def testOctetsEncoding(self):
        self.assertEqual(tools.EncodeOctets('0x01020304'), b'\x01\x02\x03\x04')
        self.assertEqual(tools.EncodeOctets(b'0x01020304'), b'\x01\x02\x03\x04')
        self.assertEqual(tools.EncodeOctets('16909060'), b'\x01\x02\x03\x04')
        # encodes to 253 bytes
        self.assertEqual(tools.EncodeOctets('0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D'), b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r')
        self.assertRaisesRegex(ValueError, 'Can only encode strings of <= 253 characters', tools.EncodeOctets, '0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E')

    def testUnknownTypeEncoding(self):
        self.assertRaises(ValueError, tools.EncodeAttr, 'unknown', None)

    def testUnknownTypeDecoding(self):
        self.assertRaises(ValueError, tools.DecodeAttr, 'unknown', None)

    def testEncodeFunction(self):
        self.assertEqual(
                tools.EncodeAttr('string', 'string'),
                b'string')
        self.assertEqual(
                tools.EncodeAttr('octets', b'string'),
                b'string')
        self.assertEqual(
                tools.EncodeAttr('ipaddr', '192.168.0.255'),
                b'\xc0\xa8\x00\xff')
        self.assertEqual(
                tools.EncodeAttr('integer', 0x01020304),
                b'\x01\x02\x03\x04')
        self.assertEqual(
                tools.EncodeAttr('date', 0x01020304),
                b'\x01\x02\x03\x04')
        self.assertEqual(
                tools.EncodeAttr('integer64', 0xFFFFFFFFFFFFFFFF),
                b'\xff'*8)

    def testDecodeFunction(self):
        self.assertEqual(
                tools.DecodeAttr('string', b'string'),
                'string')
        self.assertEqual(
                tools.EncodeAttr('octets', b'string'),
                b'string')
        self.assertEqual(
                tools.DecodeAttr('ipaddr', b'\xc0\xa8\x00\xff'),
                '192.168.0.255')
        self.assertEqual(
                tools.DecodeAttr('integer', b'\x01\x02\x03\x04'),
                0x01020304)
        self.assertEqual(
                tools.DecodeAttr('integer64', b'\xff'*8),
                0xFFFFFFFFFFFFFFFF)
        self.assertEqual(
                tools.DecodeAttr('date', b'\x01\x02\x03\x04'),
                0x01020304)


class DecodeLengthTests(unittest.TestCase):
    """Values with a wrong length raise a ValueError, not struct.error (#13)."""

    def testFixedLengthTypes(self):
        for datatype, length in (('integer', 4), ('signed', 4), ('short', 2),
                                 ('byte', 1), ('date', 4), ('integer64', 8),
                                 ('ipaddr', 4)):
            for value in (b'', b'\x01' * (length - 1), b'\x01' * (length + 1)):
                with self.subTest(datatype=datatype, length=len(value)):
                    self.assertRaises(ValueError, tools.DecodeAttr, datatype, value)

    def testIPv6Address(self):
        self.assertRaises(ValueError, tools.DecodeAttr, 'ipv6addr', 17 * b'\x00')

    def testIPv6Prefix(self):
        for value in (b'', b'\x00', 19 * b'\x00'):
            with self.subTest(length=len(value)):
                self.assertRaises(ValueError, tools.DecodeAttr, 'ipv6prefix', value)
        self.assertRaises(ValueError, tools.DecodeAttr, 'ipv6prefix', b'\x00\x81')


class OctetsEncodingTests(unittest.TestCase):
    def testNone(self):
        self.assertEqual(tools.EncodeOctets(None), b'')

    def testBytes(self):
        self.assertEqual(tools.EncodeOctets(b'\x00\x01'), b'\x00\x01')
        self.assertEqual(tools.EncodeOctets(bytearray(b'ab')), b'ab')

    def testHexBytes(self):
        self.assertEqual(tools.EncodeOctets(b'0x0102ff'), b'\x01\x02\xff')

    def testHexString(self):
        self.assertEqual(tools.EncodeOctets('0x0102ff'), b'\x01\x02\xff')

    def testDecimalString(self):
        self.assertEqual(tools.EncodeOctets('65'), b'A')
        self.assertEqual(tools.EncodeOctets('256'), b'\x01\x00')

    def testString(self):
        self.assertEqual(tools.EncodeOctets('abc'), b'abc')

    def testTooLong(self):
        self.assertRaises(ValueError, tools.EncodeOctets, b'x' * 254)
        self.assertRaises(ValueError, tools.EncodeOctets, 'x' * 254)

    def testInvalidType(self):
        self.assertRaises(TypeError, tools.EncodeOctets, 1)


class StringEncodingTests(unittest.TestCase):
    def testNone(self):
        self.assertEqual(tools.EncodeString(None), b'')

    def testBytes(self):
        self.assertEqual(tools.EncodeString(b'abc'), b'abc')
        self.assertRaises(ValueError, tools.EncodeString, b'x' * 254)


class IPv6EncodingTests(unittest.TestCase):
    ADDRESS = b'\x20\x01\x0d\xb8' + 11 * b'\x00' + b'\x01'

    def testAddress(self):
        self.assertEqual(tools.EncodeIPv6Address('2001:db8::1'), self.ADDRESS)
        self.assertEqual(
            tools.EncodeIPv6Address(ipaddress.IPv6Address('2001:db8::1')), self.ADDRESS)
        self.assertRaises(TypeError, tools.EncodeIPv6Address, 1)
        self.assertRaises(ValueError, tools.EncodeIPv6Address, '192.168.0.1')

    def testDecodeAddress(self):
        self.assertEqual(tools.DecodeIPv6Address(self.ADDRESS), '2001:db8::1')
        # trailing zero octets may be omitted
        self.assertEqual(tools.DecodeIPv6Address(b'\x20\x01\x0d\xb8'), '2001:db8::')

    def testPrefix(self):
        prefix = b'\x00\x40\x20\x01\x0d\xb8' + 12 * b'\x00'
        self.assertEqual(tools.EncodeIPv6Prefix('2001:db8::/64'), prefix)
        # host bits are cleared
        self.assertEqual(tools.EncodeIPv6Prefix('2001:db8::1/64'), prefix)
        self.assertEqual(
            tools.EncodeIPv6Prefix(ipaddress.IPv6Network('2001:db8::/64')), prefix)
        self.assertEqual(
            tools.EncodeIPv6Prefix(netaddr.IPNetwork('2001:db8::/64')), prefix)

    def testPrefixWithoutLength(self):
        self.assertEqual(tools.EncodeIPv6Prefix('2001:db8::1'), b'\x00\x80' + self.ADDRESS)
        self.assertEqual(
            tools.EncodeIPv6Prefix(ipaddress.IPv6Address('2001:db8::1')), b'\x00\x80' + self.ADDRESS)

    def testInvalidPrefix(self):
        self.assertRaises(TypeError, tools.EncodeIPv6Prefix, 1)
        self.assertRaises(ValueError, tools.EncodeIPv6Prefix, '192.168.0.0/24')

    def testDecodePrefix(self):
        self.assertEqual(
            tools.DecodeIPv6Prefix(b'\x00\x40\x20\x01\x0d\xb8' + 12 * b'\x00'), '2001:db8::/64')
        # only the significant octets of the prefix may be sent (RFC 3162)
        self.assertEqual(tools.DecodeIPv6Prefix(b'\x00\x20\x20\x01\x0d\xb8'), '2001:db8::/32')


class AscendBinaryTests(unittest.TestCase):
    def testDelete(self):
        self.assertEqual(tools.EncodeAscendBinary('delete'), 8 * b'\x00')

    def testIPv4Filter(self):
        value = tools.EncodeAscendBinary(
            'family=ipv4 action=accept direction=out src=10.0.0.0/8 '
            'proto=6 sport=1024 dport=80 sportq=1 dportq=2')
        self.assertEqual(value, (
            b'\x01\x01\x00\x00'                    # family, action, direction
            + b'\x0a\x00\x00\x00' + 4 * b'\x00'    # src, dst
            + b'\x08\x00\x06\x00'                  # srcl, dstl, proto
            + b'\x04\x00\x00\x50'                  # sport, dport
            + b'\x01\x02\x00\x00' + 8 * b'\x00'))  # sportq, dportq, trailer

    def testIPv6Filter(self):
        value = tools.EncodeAscendBinary('family=ipv6 action=redirect dst=2001:db8::/32')
        self.assertEqual(value[:4], b'\x03\x20\x01\x00')
        self.assertEqual(value[4:20], 16 * b'\x00')
        self.assertEqual(value[20:36], b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(value[36:38], b'\x00\x20')

    def testDecode(self):
        self.assertEqual(tools.DecodeAscendBinary(b'\x01\x02'), b'\x01\x02')


class IntegerEncodingTests(unittest.TestCase):
    def testInvalidInteger64(self):
        self.assertRaises(TypeError, tools.EncodeInteger64, 'ONE')

    def testIntegerFromString(self):
        self.assertEqual(tools.EncodeInteger('10'), b'\x00\x00\x00\x0a')


class DispatchTests(unittest.TestCase):
    VALUES = [
        ('string', 'text', b'text'),
        ('octets', b'\x00\x01', b'\x00\x01'),
        ('integer', 10, b'\x00\x00\x00\x0a'),
        ('ipaddr', '192.168.0.1', b'\xc0\xa8\x00\x01'),
        ('ipv6addr', '2001:db8::1', b'\x20\x01\x0d\xb8' + 11 * b'\x00' + b'\x01'),
        ('ipv6prefix', '2001:db8::/32', b'\x00\x20\x20\x01\x0d\xb8' + 12 * b'\x00'),
        ('signed', -1, b'\xff\xff\xff\xff'),
        ('short', 258, b'\x01\x02'),
        ('byte', 7, b'\x07'),
        ('date', 10, b'\x00\x00\x00\x0a'),
        ('integer64', 2 ** 40, b'\x00\x00\x01\x00\x00\x00\x00\x00'),
    ]

    def testRoundTrip(self):
        for (datatype, value, encoded) in self.VALUES:
            with self.subTest(datatype=datatype):
                self.assertEqual(tools.EncodeAttr(datatype, value), encoded)
                self.assertEqual(tools.DecodeAttr(datatype, encoded), value)

    def testAscendBinary(self):
        encoded = tools.EncodeAttr('abinary', 'delete')
        self.assertEqual(tools.DecodeAttr('abinary', encoded), encoded)
