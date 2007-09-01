import unittest
import os
from pyrad.tests import home
from pyrad.dictionary import Dictionary


class DictionaryInterfaceTests(unittest.TestCase):
    def testEmptyDictionary(self):
        dict=Dictionary()
        self.assertEqual(len(dict), 0)


class DictionaryParsingTests(unittest.TestCase):
    def setUp(self):
        self.path=os.path.join(home, "tests", "data")

    def testParseEmptyDictionary(self):
        dict=Dictionary(os.path.join(self.path, "empty"))
        self.assertEqual(len(dict), 0)

    def testParseSimpleDictionary(self):
        dict=Dictionary(os.path.join(self.path, "simple"))
        self.assertEqual(len(dict), 5)
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
            attr=dict[attr]
            self.assertEqual(attr.code, code)
            self.assertEqual(attr.datatype, type)

