import unittest
import operator
import os
from six import StringIO
from pyrad.tests import home
from pyrad.dictionary import Attribute
from pyrad.dictionary import Dictionary
from pyrad.dictionary import ParseError
from pyrad.tools import decode_attr
from pyrad.dictfile import DictFile


class AttributeTests(unittest.TestCase):

    def testInvalidDataType(self):
        self.assertRaises(ValueError, Attribute, 'name', 'code', 'datatype')

    def testConstructionParameters(self):
        attr = Attribute('name', 'code', 'integer', 'vendor')
        self.assertEqual(attr.name, 'name')
        self.assertEqual(attr.code, 'code')
        self.assertEqual(attr.type, 'integer')
        self.assertEqual(attr.vendor, 'vendor')
        self.assertEqual(len(attr.values), 0)

    def testNamedConstructionParameters(self):
        attr = Attribute(name='name', code='code', datatype='integer',
                         vendor='vendor')
        self.assertEqual(attr.name, 'name')
        self.assertEqual(attr.code, 'code')
        self.assertEqual(attr.type, 'integer')
        self.assertEqual(attr.vendor, 'vendor')
        self.assertEqual(len(attr.values), 0)

    def testValues(self):
        attr = Attribute('name', 'code', 'integer', 'vendor',
                         dict(pie='custard', shake='vanilla'))
        self.assertEqual(len(attr.values), 2)
        self.assertEqual(attr.values['shake'], 'vanilla')


class DictionaryInterfaceTests(unittest.TestCase):

    def testEmptyDictionary(self):
        dictionary = Dictionary()
        self.assertEqual(len(dictionary), 0)

    def testContainment(self):
        dictionary = Dictionary()
        self.assertEqual('test' in dictionary, False)
        self.assertEqual('test' in dictionary, False)
        dictionary.attributes['test'] = 'dummy'
        self.assertEqual('test' in dictionary, True)
        self.assertEqual('test' in dictionary, True)

    def testReadonlyContainer(self):
        import six
        dictionary = Dictionary()
        self.assertRaises(TypeError,
                          operator.setitem, dictionary, 'test', 'dummy')
        self.assertRaises(AttributeError,
                          operator.attrgetter('clear'), dictionary)
        self.assertRaises(AttributeError,
                          operator.attrgetter('update'), dictionary)


class DictionaryParsingTests(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dictionary = Dictionary(os.path.join(self.path, 'simple'))

    def testParseEmptyDictionary(self):
        dictionary = Dictionary(StringIO(''))
        self.assertEqual(len(dictionary), 0)

    def testParseMultipleDictionaries(self):
        dictionary = Dictionary(StringIO(''))
        self.assertEqual(len(dictionary), 0)
        one = StringIO('ATTRIBUTE Test-First 1 string')
        two = StringIO('ATTRIBUTE Test-Second 2 string')
        dictionary = Dictionary(StringIO(''), one, two)
        self.assertEqual(len(dictionary), 2)

    def testParseSimpleDictionary(self):
        self.assertEqual(len(self.dictionary), 8)
        values = [
            ('Test-String', 1, 'string'),
            ('Test-Octets', 2, 'octets'),
            ('Test-Integer', 3, 'integer'),
            ('Test-Ip-Address', 4, 'ipaddr'),
            ('Test-Ipv6-Address', 5, 'ipv6addr'),
            ('Test-If-Id', 6, 'ifid'),
            ('Test-Date', 7, 'date'),
            ('Test-Abinary', 8, 'abinary'),
        ]

        for (attr, code, type) in values:
            attr = self.dictionary[attr]
            self.assertEqual(attr.code, code)
            self.assertEqual(attr.type, type)

    def testAttributeTooFewColumnsError(self):
        try:
            self.dictionary.read_dictionary(
                StringIO('ATTRIBUTE Oops-Too-Few-Columns'))
        except ParseError as e:
            self.assertEqual('attribute' in str(e), True)
        else:
            self.fail()

    def testAttributeUnknownTypeError(self):
        try:
            self.dictionary.read_dictionary(
                    StringIO('ATTRIBUTE Test-Type 1 dummy'))
        except ParseError as e:
            self.assertEqual('dummy' in str(e), True)
        else:
            self.fail()

    def testAttributeUnknownVendorError(self):
        try:
            self.dictionary.read_dictionary(
                    StringIO('ATTRIBUTE Test-Type 1 Simplon'))
        except ParseError as e:
            self.assertEqual('Simplon' in str(e), True)
        else:
            self.fail()

    def testAttributeOptions(self):
        self.dictionary.read_dictionary(StringIO(
            'ATTRIBUTE Option-Type 1 string has_tag,encrypt=1'))
        self.assertEqual(self.dictionary['Option-Type'].has_tag, True)
        self.assertEqual(self.dictionary['Option-Type'].encrypt, 1)

    def testAttributeEncryptionError(self):
        try:
            self.dictionary.read_dictionary(StringIO(
                'ATTRIBUTE Test-Type 1 string encrypt=4'))
        except ParseError as e:
            self.assertEqual('encrypt' in str(e), True)
        else:
            self.fail()

    def testValueTooFewColumnsError(self):
        try:
            self.dictionary.read_dictionary(StringIO('VALUE Oops-Too-Few-Columns'))
        except ParseError as e:
            self.assertEqual('value' in str(e), True)
        else:
            self.fail()

    def testValueForUnknownAttributeError(self):
        try:
            self.dictionary.read_dictionary(StringIO(
                'VALUE Test-Attribute Test-Text 1'))
        except ParseError as e:
            self.assertEqual('unknown attribute' in str(e), True)
        else:
            self.fail()

    def testIntegerValueParsing(self):
        self.assertEqual(len(self.dictionary['Test-Integer'].values), 0)
        self.dictionary.read_dictionary(StringIO('VALUE Test-Integer Value-Six 5'))
        self.assertEqual(len(self.dictionary['Test-Integer'].values), 1)
        self.assertEqual(
            decode_attr('integer',
                       self.dictionary['Test-Integer'].values['Value-Six']),
            5)

    def testStringValueParsing(self):
        self.assertEqual(len(self.dictionary['Test-String'].values), 0)
        self.dictionary.read_dictionary(StringIO(
            'VALUE Test-String Value-Custard custardpie'))
        self.assertEqual(len(self.dictionary['Test-String'].values), 1)
        self.assertEqual(
            decode_attr('string',
                       self.dictionary['Test-String'].values['Value-Custard']),
            'custardpie')

    def testVenderTooFewColumnsError(self):
        try:
            self.dictionary.read_dictionary(StringIO('VENDOR Simplon'))
        except ParseError as e:
            self.assertEqual('vendor' in str(e), True)
        else:
            self.fail()

    def testVendorParsing(self):
        self.assertRaises(ParseError, self.dictionary.read_dictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        self.dictionary.read_dictionary(StringIO('VENDOR Simplon 42'))
        self.assertEqual(self.dictionary.vendors['Simplon'], 42)
        self.dictionary.read_dictionary(StringIO(
            'ATTRIBUTE Test-Type 1 integer Simplon'))
        self.assertEquals(self.dictionary.attrindex['Test-Type'], (42, 1))

    def testVendorOptionError(self):
        self.assertRaises(ParseError, self.dictionary.read_dictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dictionary.read_dictionary(StringIO('VENDOR Simplon 42 badoption'))
        except ParseError as e:
            self.assertEqual('option' in str(e), True)
        else:
            self.fail()

    def testVendorFormatError(self):
        self.assertRaises(ParseError, self.dictionary.read_dictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dictionary.read_dictionary(StringIO(
                'VENDOR Simplon 42 format=5,4'))
        except ParseError as e:
            self.assertEqual('format' in str(e), True)
        else:
            self.fail()

    def testVendorFormatSyntaxError(self):
        self.assertRaises(ParseError, self.dictionary.read_dictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dictionary.read_dictionary(StringIO(
                'VENDOR Simplon 42 format=a,1'))
        except ParseError as e:
            self.assertEqual('Syntax' in str(e), True)
        else:
            self.fail()

    def testBeginVendorTooFewColumns(self):
        try:
            self.dictionary.read_dictionary(StringIO('BEGIN-VENDOR'))
        except ParseError as e:
            self.assertEqual('begin-vendor' in str(e), True)
        else:
            self.fail()

    def testBeginVendorUnknownVendor(self):
        try:
            self.dictionary.read_dictionary(StringIO('BEGIN-VENDOR Simplon'))
        except ParseError as e:
            self.assertEqual('Simplon' in str(e), True)
        else:
            self.fail()

    def testBeginVendorParsing(self):
        self.dictionary.read_dictionary(StringIO(
            'VENDOR Simplon 42\n'
            'BEGIN-VENDOR Simplon\n'
            'ATTRIBUTE Test-Type 1 integer'))
        self.assertEquals(self.dictionary.attrindex['Test-Type'], (42, 1))

    def testEndVendorUnknownVendor(self):
        try:
            self.dictionary.read_dictionary(StringIO('END-VENDOR'))
        except ParseError as e:
            self.assertEqual('end-vendor' in str(e), True)
        else:
            self.fail()

    def testEndVendorUnbalanced(self):
        try:
            self.dictionary.read_dictionary(StringIO(
                'VENDOR Simplon 42\n'
                'BEGIN-VENDOR Simplon\n'
                'END-VENDOR Oops\n'))
        except ParseError as e:
            self.assertEqual('Oops' in str(e), True)
        else:
            self.fail()

    def testEndVendorParsing(self):
        self.dictionary.read_dictionary(StringIO(
            'VENDOR Simplon 42\n'
            'BEGIN-VENDOR Simplon\n'
            'END-VENDOR Simplon\n'
            'ATTRIBUTE Test-Type 1 integer'))
        self.assertEquals(self.dictionary.attrindex['Test-Type'], 1)

    def testInclude(self):
        try:
            self.dictionary.read_dictionary(StringIO(
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
        self.assertEquals(f.file(), '')
        self.assertEquals(f.line(), -1)

    def testDictFileParseError(self):
        tmpdict = Dictionary()
        try:
            tmpdict.read_dictionary(os.path.join(self.path, 'dictfiletest'))
        except ParseError as e:
            self.assertEquals('dictfiletest' in str(e), True)
        else:
            self.fail()
