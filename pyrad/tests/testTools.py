from netaddr import AddrFormatError
from pyrad import tools
import unittest
import six
import sys


class EncodingTests(unittest.TestCase):

    def testStringEncoding(self):
        self.assertRaises(ValueError, tools.encode_string, 'x' * 254)
        self.assertEqual(
            tools.encode_string('1234567890'),
            six.b('1234567890'))

    def testInvalidStringEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.encode_string, 1)

    def testAddressEncoding(self):
        self.assertRaises(AddrFormatError, tools.encode_address, 'TEST123')
        self.assertEqual(
            tools.encode_address('192.168.0.255'),
            six.b('\xc0\xa8\x00\xff'))

    def testInvalidAddressEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.encode_address, 1)

    def testIntegerEncoding(self):
        self.assertEqual(
            tools.encode_integer(0x01020304),
            six.b('\x01\x02\x03\x04'))

    def testUnsignedIntegerEncoding(self):
        self.assertEqual(
            tools.encode_integer(0xFFFFFFFF),
            six.b('\xff\xff\xff\xff'))

    def testInvalidIntegerEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.encode_integer, 'ONE')

    def testDateEncoding(self):
        self.assertEqual(
            tools.encode_date(0x01020304),
            six.b('\x01\x02\x03\x04'))

    def testInvalidDataEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.encode_date, '1')

    def testencode_ascend_binary(self):
        self.assertEqual(
            tools.encode_ascend_binary(
                'family=ipv4 action=discard direction=in dst=10.10.255.254/32'),
            six.b('\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))

    def testStringDecoding(self):
        self.assertEqual(
            tools.decode_string(six.b('1234567890')),
            '1234567890')

    def testAddressDecoding(self):
        self.assertEqual(
            tools.decode_address(six.b('\xc0\xa8\x00\xff')),
            '192.168.0.255')

    def testIntegerDecoding(self):
        self.assertEqual(
            tools.decode_integer(six.b('\x01\x02\x03\x04')),
            0x01020304)

    def testDateDecoding(self):
        self.assertEqual(
            tools.decode_date(six.b('\x01\x02\x03\x04')),
            0x01020304)

    def testUnknownTypeEncoding(self):
        self.assertRaises(ValueError, tools.encode_attr, 'unknown', None)

    def testUnknownTypeDecoding(self):
        self.assertRaises(ValueError, tools.decode_attr, 'unknown', None)

    def testEncodeFunction(self):
        self.assertEqual(
            tools.encode_attr('string', six.u('string')),
            six.b('string'))
        self.assertEqual(
            tools.encode_attr('octets', six.b('string')),
            six.b('string'))
        self.assertEqual(
            tools.encode_attr('ipaddr', '192.168.0.255'),
            six.b('\xc0\xa8\x00\xff'))
        self.assertEqual(
            tools.encode_attr('integer', 0x01020304),
            six.b('\x01\x02\x03\x04'))
        self.assertEqual(
            tools.encode_attr('date', 0x01020304),
            six.b('\x01\x02\x03\x04'))

    def testDecodeFunction(self):
        self.assertEqual(
            tools.decode_attr('string', six.b('string')),
            six.u('string'))
        self.assertEqual(
            tools.encode_attr('octets', six.b('string')),
            six.b('string'))
        self.assertEqual(
            tools.decode_attr('ipaddr', six.b('\xc0\xa8\x00\xff')),
            '192.168.0.255')
        self.assertEqual(
            tools.decode_attr('integer', six.b('\x01\x02\x03\x04')),
            0x01020304)
        self.assertEqual(
            tools.decode_attr('date', six.b('\x01\x02\x03\x04')),
            0x01020304)
