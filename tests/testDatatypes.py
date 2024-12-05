from ipaddress import AddressValueError
from pyrad.datatypes.leaf import *
import unittest


class LeafEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.abinary = AscendBinary()
        cls.byte = Byte()
        cls.date = Date()
        cls.ether = Ether()
        cls.ifid = Ifid()
        cls.integer = Integer()
        cls.integer64 = Integer64()
        cls.ipaddr = Ipaddr()
        cls.ipv6addr = Ipv6addr()
        cls.ipv6prefix = Ipv6prefix()
        cls.octets = Octets()
        cls.short = Short()
        cls.signed = Signed()
        cls.string = String()

    def testStringEncoding(self):
        self.assertRaises(ValueError, self.string.encode, None, 'x' * 254)
        self.assertEqual(
                self.string.encode(None, '1234567890'),
                b'1234567890')

    def testInvalidStringEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, self.string.encode, None, 1)

    def testAddressEncoding(self):
        self.assertRaises(AddressValueError, self.ipaddr.encode, None,'TEST123')
        self.assertEqual(
                self.ipaddr.encode(None, '192.168.0.255'),
                b'\xc0\xa8\x00\xff')

    def testInvalidAddressEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, self.ipaddr.encode, None, 1)

    def testIntegerEncoding(self):
        self.assertEqual(self.integer.encode(None, 0x01020304), b'\x01\x02\x03\x04')

    def testInteger64Encoding(self):
        self.assertEqual(
            self.integer64.encode(None, 0xFFFFFFFFFFFFFFFF), b'\xff' * 8
        )

    def testUnsignedIntegerEncoding(self):
        self.assertEqual(self.integer.encode(None, 0xFFFFFFFF), b'\xff\xff\xff\xff')

    def testInvalidIntegerEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, self.integer.encode, None, 'ONE')

    def testDateEncoding(self):
        self.assertEqual(self.date.encode(None, 0x01020304), b'\x01\x02\x03\x04')

    def testInvalidDataEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, self.date.encode, None, '1')

    def testEncodeAscendBinary(self):
        self.assertEqual(
            self.abinary.encode(None, 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'),
            b'\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testStringDecoding(self):
        self.assertEqual(
                self.string.decode(b'1234567890'),
                '1234567890')

    def testAddressDecoding(self):
        self.assertEqual(
                self.ipaddr.decode(b'\xc0\xa8\x00\xff'),
                '192.168.0.255')

    def testIntegerDecoding(self):
        self.assertEqual(
                self.integer.decode(b'\x01\x02\x03\x04'),
                0x01020304)

    def testInteger64Decoding(self):
        self.assertEqual(
            self.integer64.decode(b'\xff' * 8), 0xFFFFFFFFFFFFFFFF
        )

    def testDateDecoding(self):
        self.assertEqual(
                self.date.decode(b'\x01\x02\x03\x04'),
                0x01020304)

    def testOctetsEncoding(self):
        self.assertEqual(self.octets.encode(None, '0x01020304'), b'\x01\x02\x03\x04')
        self.assertEqual(self.octets.encode(None, b'0x01020304'), b'\x01\x02\x03\x04')
        self.assertEqual(self.octets.encode(None, '16909060'), b'\x01\x02\x03\x04')
        # encodes to 253 bytes
        self.assertEqual(self.octets.encode(None, '0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D'), b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r')
        self.assertRaisesRegex(ValueError, 'Can only encode strings of <= 253 characters', self.octets.encode, None, '0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E')
