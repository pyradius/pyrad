import unittest
import operator
import os
import tempfile
from io import StringIO

from . import home
from pyrad.dictionary import Attribute
from pyrad.dictionary import Dictionary
from pyrad.dictionary import ParseError
from pyrad.tools import DecodeAttr
from pyrad.dictfile import DictFile


class AttributeTests(unittest.TestCase):
    def testInvalidDataType(self):
        self.assertRaises(ValueError, Attribute, 'name', 'code', 'datatype')

    def testConstructionParameters(self):
        attr = Attribute('name', 'code', 'integer', False, 'vendor')
        self.assertEqual(attr.name, 'name')
        self.assertEqual(attr.code, 'code')
        self.assertEqual(attr.type, 'integer')
        self.assertEqual(attr.is_sub_attribute, False)
        self.assertEqual(attr.vendor, 'vendor')
        self.assertEqual(len(attr.values), 0)
        self.assertEqual(len(attr.sub_attributes), 0)

    def testNamedConstructionParameters(self):
        attr = Attribute(name='name', code='code', datatype='integer',
                         vendor='vendor')
        self.assertEqual(attr.name, 'name')
        self.assertEqual(attr.code, 'code')
        self.assertEqual(attr.type, 'integer')
        self.assertEqual(attr.vendor, 'vendor')
        self.assertEqual(len(attr.values), 0)

    def testValues(self):
        attr = Attribute('name', 'code', 'integer', False, 'vendor',
                         dict(pie='custard', shake='vanilla'))
        self.assertEqual(len(attr.values), 2)
        self.assertEqual(attr.values['shake'], 'vanilla')


class DictionaryInterfaceTests(unittest.TestCase):
    def testEmptyDictionary(self):
        dict = Dictionary()
        self.assertEqual(len(dict), 0)

    def testContainment(self):
        dict = Dictionary()
        self.assertEqual('test' in dict, False)
        self.assertEqual(dict.has_key('test'), False)
        dict.attributes['test'] = 'dummy'
        self.assertEqual('test' in dict, True)
        self.assertEqual(dict.has_key('test'), True)

    def testReadonlyContainer(self):
        dict = Dictionary()
        self.assertRaises(TypeError,
                          operator.setitem, dict, 'test', 'dummy')
        self.assertRaises(AttributeError,
                          operator.attrgetter('clear'), dict)
        self.assertRaises(AttributeError,
                          operator.attrgetter('update'), dict)


class DictionaryParsingTests(unittest.TestCase):

    simple_dict_values = [
        ('Test-String', 1, 'string'),
        ('Test-Octets', 2, 'octets'),
        ('Test-Integer', 0x03, 'integer'),
        ('Test-Ip-Address', 4, 'ipaddr'),
        ('Test-Ipv6-Address', 5, 'ipv6addr'),
        ('Test-If-Id', 6, 'ifid'),
        ('Test-Date', 7, 'date'),
        ('Test-Abinary', 8, 'abinary'),
        ('Test-Tlv', 9, 'tlv'),
        ('Test-Tlv-Str', 1, 'string'),
        ('Test-Tlv-Int', 2, 'integer'),
        ('Test-Integer64', 10, 'integer64'),
        ('Test-Integer64-Hex', 10, 'integer64'),
        ('Test-Integer64-Oct', 10, 'integer64'),
    ]

    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'simple'))

    def testParseEmptyDictionary(self):
        dict = Dictionary(StringIO(''))
        self.assertEqual(len(dict), 0)

    def testParseMultipleDictionaries(self):
        dict = Dictionary(StringIO(''))
        self.assertEqual(len(dict), 0)
        one = StringIO('ATTRIBUTE Test-First 1 string')
        two = StringIO('ATTRIBUTE Test-Second 2 string')
        dict = Dictionary(StringIO(''), one, two)
        self.assertEqual(len(dict), 2)

    def testParseSimpleDictionary(self):
        self.assertEqual(len(self.dict), len(self.simple_dict_values))
        for (attr, code, type) in self.simple_dict_values:
            attr = self.dict[attr]
            self.assertEqual(attr.code, code)
            self.assertEqual(attr.type, type)

    def testAttributeTooFewColumnsError(self):
        try:
            self.dict.ReadDictionary(
                    StringIO('ATTRIBUTE Oops-Too-Few-Columns'))
        except ParseError as e:
            self.assertEqual('attribute' in str(e), True)
        else:
            self.fail()

    def testAttributeTooFewColumnsErrorHasFile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'dictionary.broken')
            with open(path, 'w') as fd:
                fd.write('\nATTRIBUTE Oops-Too-Few-Columns\n')
            with self.assertRaises(ParseError) as cm:
                self.dict.ReadDictionary(path)
        self.assertEqual(cm.exception.file, 'dictionary.broken')
        self.assertEqual(cm.exception.line, 2)
        self.assertTrue(str(cm.exception).startswith('dictionary.broken(2): '))

    def testAttributeUnknownTypeError(self):
        try:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Type 1 dummy'))
        except ParseError as e:
            self.assertEqual('dummy' in str(e), True)
        else:
            self.fail()

    def testAttributeUnknownVendorError(self):
        try:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Type 1 Simplon'))
        except ParseError as e:
            self.assertEqual('Simplon' in str(e), True)
        else:
            self.fail()

    def testAttributeConcatFlag(self):
        # FreeRADIUS compatibility, the values are not concatenated
        self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Concat 99 octets concat'))
        self.assertEqual(self.dict['Test-Concat'].type, 'octets')
        self.assertEqual(self.dict.attrindex['Test-Concat'], 99)

    def testNestedTlvIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Nested 1.2.3 string'))
        self.assertFalse('Test-Nested' in self.dict)
        self.assertIn('Test-Nested', self.dict.skipped_attributes)
        self.assertIn('nested TLV', cm.output[0])

    def testSubTlvIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Top 90 tlv\n'
                'ATTRIBUTE Test-Inner 90.3 tlv\n'
                'ATTRIBUTE Test-Inner-Str 90.3.1 string\n'
                'ATTRIBUTE Test-Top-Str 90.1 string'))
        self.assertFalse('Test-Inner' in self.dict)
        self.assertFalse('Test-Inner-Str' in self.dict)
        self.assertEqual(self.dict['Test-Top'].sub_attributes, {1: 'Test-Top-Str'})
        self.assertIn('nested TLV', cm.output[0])

    def testSkippedCodeKeepsTopLevelAttribute(self):
        with self.assertLogs('pyrad', 'WARNING'):
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Bool 200 bool\n'
                'ATTRIBUTE Test-Integer-200 200 integer'))
        self.assertEqual(self.dict.attrindex['Test-Integer-200'], 200)

    def testSubAttributeOfUnknownTlvError(self):
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Sub 99.1 string'))
        self.assertIn('unknown TLV 99', str(cm.exception))

    def testSubAttributeOfTlvOfOtherVendor(self):
        self.dict.ReadDictionary(StringIO(
            'VENDOR Test-Vendor 42\n'
            'ATTRIBUTE Test-Vendor-Tlv 9 tlv Test-Vendor\n'
            'ATTRIBUTE Test-Std-Sub 9.3 string'))
        # 9 is Test-Tlv of the standard space in the simple dictionary
        self.assertIs(self.dict['Test-Std-Sub'].parent, self.dict['Test-Tlv'])
        self.assertEqual(self.dict['Test-Tlv'].sub_attributes[3],
                         'Test-Std-Sub')
        self.assertNotIn(3, self.dict['Test-Vendor-Tlv'].sub_attributes)
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO(
                'BEGIN-VENDOR Test-Vendor\n'
                'ATTRIBUTE Test-Vendor-Sub 90.1 string\n'
                'END-VENDOR Test-Vendor'))
        self.assertIn('unknown TLV 90', str(cm.exception))
        self.assertEqual(cm.exception.line, 2)

    def testSubAttributeOfTlvInOtherFile(self):
        dict = Dictionary(
            StringIO('ATTRIBUTE Test-Tlv 9 tlv'),
            StringIO('ATTRIBUTE Test-Tlv-Str 9.1 string'))
        self.assertIs(dict['Test-Tlv-Str'].parent, dict['Test-Tlv'])
        self.assertEqual(dict['Test-Tlv'].sub_attributes, {1: 'Test-Tlv-Str'})

    def testSubAttributeOfSkippedAttributeInOtherFile(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(
                StringIO('ATTRIBUTE Test-Extended 241 extended'),
                StringIO('ATTRIBUTE Test-Ext-String 241.5 string'))
        self.assertIn('Test-Ext-String', dict.skipped_attributes)

    def testRedefinedSkippedAttributeAsTlv(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(StringIO('ATTRIBUTE Test-Bool 200 bool'))
        dict.ReadDictionary(StringIO(
            'ATTRIBUTE Test-Tlv 200 tlv\n'
            'ATTRIBUTE Test-Tlv-Str 200.1 string'))
        self.assertEqual(dict['Test-Tlv'].sub_attributes, {1: 'Test-Tlv-Str'})

    def testAttributeFreeRadiusFlags(self):
        self.dict.ReadDictionary(StringIO(
            'ATTRIBUTE Test-Secret 90 octets secret\n'
            'ATTRIBUTE Test-Virtual 1000 integer virtual\n'
            'ATTRIBUTE Test-Password 91 string encrypt=1,secret'))
        self.assertEqual(self.dict['Test-Secret'].type, 'octets')
        self.assertEqual(self.dict['Test-Secret'].vendor, '')
        self.assertEqual(self.dict.attrindex['Test-Virtual'], 1000)
        self.assertEqual(self.dict['Test-Password'].encrypt, 1)

    def testAttributeArrayIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Array 90 ipaddr array'))
        self.assertFalse('Test-Array' in self.dict)
        self.assertIn('array flag', cm.output[0])

    def testAttributeVendorNamedLikeFlag(self):
        self.dict.ReadDictionary(StringIO(
            'VENDOR secret 42\n'
            'ATTRIBUTE Test-Type 1 integer secret'))
        self.assertEqual(self.dict['Test-Type'].vendor, 'secret')
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))

    def testUnsupportedDataTypeIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Extended 241 extended\n'
                'ATTRIBUTE Test-Evs 241.26 evs\n'
                'ATTRIBUTE Test-Ext-String 241.5 string\n'
                'VALUE Test-Ext-String Any any\n'
                'ATTRIBUTE Test-Ext-Vsa 241.26.42.1 string\n'
                'ATTRIBUTE Test-After 90 string'))
        for attr in ('Test-Extended', 'Test-Evs', 'Test-Ext-String',
                     'Test-Ext-Vsa'):
            self.assertFalse(attr in self.dict)
            self.assertIn(attr, self.dict.skipped_attributes)
        self.assertEqual(self.dict.attrindex['Test-After'], 90)
        self.assertEqual(len(cm.output), 1)
        self.assertIn('Skipped 4 unsupported dictionary attributes',
                      cm.output[0])
        self.assertIn('data type extended', cm.output[0])

    def testParseFreeRadiusDictionary(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(os.path.join(self.path, 'freeradius'))
        self.assertEqual(dict['User-Password'].encrypt, 1)
        self.assertEqual(dict['CHAP-Password'].type, 'octets')
        self.assertEqual(dict['Tunnel-Password'].has_tag, True)
        self.assertEqual(dict['Tunnel-Password'].encrypt, 2)
        self.assertEqual(dict.attrindex['Proxy-To-Realm'], 1031)
        self.assertEqual(dict.attrindex['FreeRADIUS-Proxied-To'], (11344, 1))
        self.assertEqual(dict['EAP-Message'].type, 'octets')
        self.assertEqual(dict.skipped_attributes, set([
            'Vendor-Specific', 'Mobile-Node-Home-Address-IPv4',
            'Extended-Attribute-1', 'Extended-Attribute-5',
            'Extended-Vendor-Specific-1', 'Extended-Vendor-Specific-5',
            'Allowed-Called-Station-Id', 'FreeRADIUS-Attr',
            'FreeRADIUS-EAP-FAST-PAC', 'FreeRADIUS-EAP-FAST-PAC-Key',
            'WiMAX-Capability', 'WiMAX-Release', 'WiMAX-DNS-Server',
            'Lucent-Max-Shared-Users', 'DHCP-Router-Address']))

    def testAttributeOptions(self):
        self.dict.ReadDictionary(StringIO(
            'ATTRIBUTE Option-Type 1 string has_tag,encrypt=1'))
        self.assertEqual(self.dict['Option-Type'].has_tag, True)
        self.assertEqual(self.dict['Option-Type'].encrypt, 1)

    def testAttributeEncryptionError(self):
        try:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Type 1 string encrypt=4'))
        except ParseError as e:
            self.assertEqual('encrypt' in str(e), True)
        else:
            self.fail()

    def testValueTooFewColumnsError(self):
        try:
            self.dict.ReadDictionary(StringIO('VALUE Oops-Too-Few-Columns'))
        except ParseError as e:
            self.assertEqual('value' in str(e), True)
        else:
            self.fail()

    def testValueForUnknownAttributeIsIgnored(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'VALUE Test-Attribute Test-Text 1'))
        self.assertFalse('Test-Attribute' in self.dict)
        self.assertIn('unknown attribute Test-Attribute', cm.output[0])

    def testIntegerValueParsing(self):
        self.assertEqual(len(self.dict['Test-Integer'].values), 0)
        self.dict.ReadDictionary(StringIO('VALUE Test-Integer Value-Six 5'))
        self.assertEqual(len(self.dict['Test-Integer'].values), 1)
        self.assertEqual(
                DecodeAttr('integer',
                           self.dict['Test-Integer'].values['Value-Six']),
                5)

    def testDateValueParsing(self):
        self.dict.ReadDictionary(StringIO('VALUE Test-Date Epoch-Plus-One 1'))
        self.assertEqual(self.dict['Test-Date'].values['Epoch-Plus-One'],
                         b'\x00\x00\x00\x01')

    def testIllegalValueError(self):
        self.dict.ReadDictionary(StringIO(
            'ATTRIBUTE Test-Byte 20 byte\n'
            'ATTRIBUTE Test-Ether 21 ether'))
        for (attr, value) in [('Test-Integer', '010'),
                              ('Test-Integer', 'abc'),
                              ('Test-Date', 'tomorrow'),
                              ('Test-Byte', '256'),
                              ('Test-Ether', 'not-a-mac'),
                              ('Test-Ip-Address', '1.2.3.400')]:
            with self.subTest(attr=attr, value=value):
                with self.assertRaises(ParseError) as cm:
                    self.dict.ReadDictionary(StringIO(
                        '\nVALUE %s Test-Value %s' % (attr, value)))
                self.assertEqual(cm.exception.line, 2)
                self.assertIn(attr, str(cm.exception))

    def testIllegalAttributeCodeError(self):
        for code in ['0X1A', 'abc', '9.x']:
            with self.subTest(code=code):
                with self.assertRaises(ParseError) as cm:
                    self.dict.ReadDictionary(StringIO(
                        '\nATTRIBUTE Test-Code %s string' % code))
                self.assertEqual(cm.exception.line, 2)
                self.assertIn(code, str(cm.exception))

    def testIllegalVendorCodeError(self):
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO('\nVENDOR Simplon abc'))
        self.assertEqual(cm.exception.line, 2)
        self.assertIn('abc', str(cm.exception))

    def testInteger64ValueParsing(self):
        self.assertEqual(len(self.dict['Test-Integer64'].values), 0)
        self.dict.ReadDictionary(StringIO('VALUE Test-Integer64 Value-Six 5'))
        self.assertEqual(len(self.dict['Test-Integer64'].values), 1)
        self.assertEqual(
                DecodeAttr('integer64',
                           self.dict['Test-Integer64'].values['Value-Six']),
                5)

    def testStringValueParsing(self):
        self.assertEqual(len(self.dict['Test-String'].values), 0)
        self.dict.ReadDictionary(StringIO(
            'VALUE Test-String Value-Custard custardpie'))
        self.assertEqual(len(self.dict['Test-String'].values), 1)
        self.assertEqual(
                DecodeAttr('string',
                           self.dict['Test-String'].values['Value-Custard']),
                'custardpie')

    def testOctetValueParsing(self):
        self.assertEqual(len(self.dict['Test-Octets'].values), 0)
        self.dict.ReadDictionary(StringIO(
                        'ATTRIBUTE Test-Octets 1 octets\n'
                        'VALUE Test-Octets Value-A 65\n'      # "A"
                        'VALUE Test-Octets Value-B 0x42\n'))  # "B"
        self.assertEqual(len(self.dict['Test-Octets'].values), 2)
        self.assertEqual(
                DecodeAttr('octets',
                           self.dict['Test-Octets'].values['Value-A']),
                b'A')
        self.assertEqual(
                DecodeAttr('octets',
                           self.dict['Test-Octets'].values['Value-B']),
                b'B')

    def testTlvParsing(self):
        self.assertEqual(len(self.dict['Test-Tlv'].sub_attributes), 2)
        self.assertEqual(self.dict['Test-Tlv'].sub_attributes, {1: 'Test-Tlv-Str', 2: 'Test-Tlv-Int'})

    def testSubTlvParsing(self):
        for (attr, _, _) in self.simple_dict_values:
            if attr.startswith('Test-Tlv-'):
                self.assertEqual(self.dict[attr].is_sub_attribute, True)
                self.assertEqual(self.dict[attr].parent, self.dict['Test-Tlv'])
            else:
                self.assertEqual(self.dict[attr].is_sub_attribute, False)
                self.assertEqual(self.dict[attr].parent, None)

        # tlv with vendor
        full_dict = Dictionary(os.path.join(self.path, 'full'))
        self.assertEqual(full_dict['Simplon-Tlv-Str'].is_sub_attribute, True)
        self.assertEqual(full_dict['Simplon-Tlv-Str'].parent, full_dict['Simplon-Tlv'])
        self.assertEqual(full_dict['Simplon-Tlv-Int'].is_sub_attribute, True)
        self.assertEqual(full_dict['Simplon-Tlv-Int'].parent, full_dict['Simplon-Tlv'])

    def testVenderTooFewColumnsError(self):
        try:
            self.dict.ReadDictionary(StringIO('VENDOR Simplon'))
        except ParseError as e:
            self.assertEqual('vendor' in str(e), True)
        else:
            self.fail()

    def testVendorParsing(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        self.dict.ReadDictionary(StringIO('VENDOR Simplon 42'))
        self.assertEqual(self.dict.vendors['Simplon'], 42)
        self.dict.ReadDictionary(StringIO(
                        'ATTRIBUTE Test-Type 1 integer Simplon'))
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))

    def testVendorOptionError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dict.ReadDictionary(StringIO('VENDOR Simplon 42 badoption'))
        except ParseError as e:
            self.assertEqual('option' in str(e), True)
        else:
            self.fail()

    def testVendorFormatError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dict.ReadDictionary(StringIO(
                'VENDOR Simplon 42 format=5,4'))
        except ParseError as e:
            self.assertEqual('format' in str(e), True)
        else:
            self.fail()

    def testVendorFormatIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'VENDOR WiMAX 24757 format=1,1,c\n'
                'VENDOR Lucent 4846 format=2,1\n'
                'VENDOR USR 429 format=4,0\n'
                'VENDOR Simplon 42 format=1,1\n'
                'ATTRIBUTE WiMAX-Release 1 string WiMAX\n'
                'BEGIN-VENDOR Lucent\n'
                'ATTRIBUTE Lucent-Max-Shared-Users 2 integer\n'
                'END-VENDOR Lucent\n'
                'BEGIN-VENDOR USR\n'
                'ATTRIBUTE USR-Last-Number-Dialed-Out 102 string\n'
                'END-VENDOR USR\n'
                'BEGIN-VENDOR Simplon\n'
                'ATTRIBUTE Test-Type 1 integer\n'
                'END-VENDOR Simplon'))
        self.assertEqual(self.dict.vendors['WiMAX'], 24757)
        for attr in ('WiMAX-Release', 'Lucent-Max-Shared-Users',
                     'USR-Last-Number-Dialed-Out'):
            self.assertFalse(attr in self.dict)
            self.assertIn(attr, self.dict.skipped_attributes)
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))
        self.assertIn('Skipped 3 unsupported dictionary attributes (vendor format)',
                      cm.output[0])

    def testVendorFormatSyntaxError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dict.ReadDictionary(StringIO(
                'VENDOR Simplon 42 format=a,1'))
        except ParseError as e:
            self.assertEqual('Syntax' in str(e), True)
        else:
            self.fail()

    def testBeginVendorTooFewColumns(self):
        try:
            self.dict.ReadDictionary(StringIO('BEGIN-VENDOR'))
        except ParseError as e:
            self.assertEqual('begin-vendor' in str(e), True)
        else:
            self.fail()

    def testBeginVendorUnknownVendor(self):
        try:
            self.dict.ReadDictionary(StringIO('BEGIN-VENDOR Simplon'))
        except ParseError as e:
            self.assertEqual('Simplon' in str(e), True)
        else:
            self.fail()

    def testBeginVendorOptionError(self):
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO(
                            'VENDOR Simplon 42\n'
                            'BEGIN-VENDOR Simplon parent=Oops'))
        self.assertIn('parent=Oops', str(cm.exception))

    def testBeginVendorFormatIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                            'VENDOR Simplon 42\n'
                            'BEGIN-VENDOR Simplon format=Extended-Vendor-Specific-5\n'
                            'ATTRIBUTE Test-Evs 1 integer\n'
                            'END-VENDOR Simplon\n'
                            'BEGIN-VENDOR Simplon\n'
                            'ATTRIBUTE Test-Type 1 integer\n'
                            'END-VENDOR Simplon'))
        self.assertFalse('Test-Evs' in self.dict)
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))
        self.assertIn('extended vendor-specific attribute', cm.output[0])

    def testBeginVendorParsing(self):
        self.dict.ReadDictionary(StringIO(
                        'VENDOR Simplon 42\n'
                        'BEGIN-VENDOR Simplon\n'
                        'ATTRIBUTE Test-Type 1 integer'))
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))

    def testEndVendorUnknownVendor(self):
        try:
            self.dict.ReadDictionary(StringIO('END-VENDOR'))
        except ParseError as e:
            self.assertEqual('end-vendor' in str(e), True)
        else:
            self.fail()

    def testEndVendorUnbalanced(self):
        try:
            self.dict.ReadDictionary(StringIO(
                            'VENDOR Simplon 42\n'
                            'BEGIN-VENDOR Simplon\n'
                            'END-VENDOR Oops\n'))
        except ParseError as e:
            self.assertEqual('Oops' in str(e), True)
        else:
            self.fail()

    def testEndVendorParsing(self):
        self.dict.ReadDictionary(StringIO(
                        'VENDOR Simplon 42\n'
                        'BEGIN-VENDOR Simplon\n'
                        'END-VENDOR Simplon\n'
                        'ATTRIBUTE Test-Type 1 integer'))
        self.assertEqual(self.dict.attrindex['Test-Type'], 1)

    def testInclude(self):
        try:
            self.dict.ReadDictionary(StringIO(
                    '$INCLUDE this_file_does_not_exist\n'
                    'VENDOR Simplon 42\n'
                    'BEGIN-VENDOR Simplon\n'
                    'END-VENDOR Simplon\n'
                    'ATTRIBUTE Test-Type 1 integer'))
        except IOError as e:
            self.assertEqual('this_file_does_not_exist' in str(e), True)
        else:
            self.fail()

    def testDictFilePostParse(self):
        f = DictFile(StringIO(
                'VENDOR Simplon 42\n'))
        for _ in f:
            pass
        self.assertEqual(f.File(), '')
        self.assertEqual(f.Line(), -1)

    def testDictFileParseError(self):
        tmpdict = Dictionary()
        try:
            tmpdict.ReadDictionary(os.path.join(self.path, 'dictfiletest'))
        except ParseError as e:
            self.assertEqual('dictfiletest' in str(e), True)
        else:
            self.fail()
