import unittest
import operator
import os
from StringIO import StringIO
from pyrad.tests import home
from pyrad.dictionary import Attribute
from pyrad.dictionary import Dictionary
from pyrad.dictionary import ParseError
from pyrad.tools import DecodeAttr


class DictionaryInterfaceTests(unittest.TestCase):
    def testEmptyDictionary(self):
        dict=Dictionary()
        self.assertEqual(len(dict), 0)


    def testContainment(self):
        dict=Dictionary()
        self.assertEqual("test" in dict, False)
        self.assertEqual(dict.has_key("test"), False)
        dict.attributes["test"]="dummy"
        self.assertEqual("test" in dict, True)
        self.assertEqual(dict.has_key("test"), True)


    def testReadonlyContainer(self):
        dict=Dictionary()
        self.assertRaises(AttributeError,
                operator.setitem, dict, "test", "dummy")
        self.assertRaises(AttributeError,
                operator.attrgetter("clear"), dict)
        self.assertRaises(AttributeError,
                operator.attrgetter("update"), dict)



class DictionaryParsingTests(unittest.TestCase):
    def setUp(self):
        self.path=os.path.join(home, "tests", "data")
        self.dict=Dictionary(os.path.join(self.path, "simple"))


    def testParseEmptyDictionary(self):
        dict=Dictionary(StringIO(""))
        self.assertEqual(len(dict), 0)


    def testParseSimpleDictionary(self):
        self.assertEqual(len(self.dict), 8)
        values = [
                ( "Test-String", 1, "string" ),
                ( "Test-Octets", 2, "octets" ),
                ( "Test-Integer", 3, "integer" ),
                ( "Test-Ip-Address", 4, "ipaddr" ),
                ( "Test-Ipv6-Address", 5, "ipv6addr" ),
                ( "Test-If-Id", 6, "ifid" ),
                ( "Test-Date", 7, "date" ),
                ( "Test-Abinary", 8, "abinary" ),
                ]

        for (attr, code, type) in values:
            attr=self.dict[attr]
            self.assertEqual(attr.code, code)
            self.assertEqual(attr.type, type)

    def testAttributeTooFewColumnsError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("ATTRIBUTE Oops-Too-Few-Columns"))
        try:
            self.dict.ReadDictionary(StringIO("ATTRIBUTE Oops-Too-Few-Columns"))
        except ParseError, e:
            self.assertEqual(e.linenumber, 1)
            self.assertEqual("attribute" in str(e), True)


    def testAttributeUnknownTypeError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("ATTRIBUTE Test-Type 1 dummy"))
        try:
            self.dict.ReadDictionary(StringIO("ATTRIBUTE Test-Type 1 dummy"))
        except ParseError, e:
            self.assertEqual(e.linenumber, 1)
            self.assertEqual("dummy" in str(e), True)


    def testAttributeUnknownVendorError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        try:
            self.dict.ReadDictionary(StringIO("ATTRIBUTE Test-Type 1 Simplon"))
        except ParseError, e:
            self.assertEqual(e.linenumber, 1)
            self.assertEqual("Simplon" in str(e), True)


    def testValueTooFewColumnsError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("VALUE Oops-Too-Few-Columns"))
        try:
            self.dict.ReadDictionary(StringIO("VALUE Oops-Too-Few-Columns"))
        except ParseError, e:
            self.assertEqual(e.linenumber, 1)
            self.assertEqual("value" in str(e), True)


    def testValueForUnknownAttributeError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("VALUE Test-Attribute Test-Text 1"))
        try:
            self.dict.ReadDictionary(StringIO("VALUE Test-Attribute Test-Text 1"))
        except ParseError, e:
            self.assertEqual(e.linenumber, 1)
            self.assertEqual("unknown attribute" in str(e), True)


    def testIntegerValueParsing(self):
        self.assertEqual(len(self.dict["Test-Integer"].values), 0)
        self.dict.ReadDictionary(StringIO("VALUE Test-Integer Value-Six 5"))
        self.assertEqual(len(self.dict["Test-Integer"].values), 1)
        self.assertEqual(
                DecodeAttr("integer", self.dict["Test-Integer"].values["Value-Six"]),
                5)


    def testStringValueParsing(self):
        self.assertEqual(len(self.dict["Test-String"].values), 0)
        self.dict.ReadDictionary(StringIO("VALUE Test-String Value-Custard custardpie"))
        self.assertEqual(len(self.dict["Test-String"].values), 1)
        self.assertEqual(
                DecodeAttr("string", self.dict["Test-String"].values["Value-Custard"]),
                "custardpie")


    def testVenderTooFewColumnsError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("VENDOR Simplon"))
        try:
            self.dict.ReadDictionary(StringIO("VENDOR Simplon"))
        except ParseError, e:
            self.assertEqual(e.linenumber, 1)
            self.assertEqual("vendor" in str(e), True)


    def testVenderParsing(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        self.dict.ReadDictionary(StringIO("VENDOR Simplon 42"))
        self.assertEqual(self.dict.vendors["Simplon"], 42)
        self.dict.ReadDictionary(StringIO(
                        "ATTRIBUTE Test-Type 1 integer Simplon"))
        self.assertEquals(self.dict.attrindex["Test-Type"], (42, 1))

