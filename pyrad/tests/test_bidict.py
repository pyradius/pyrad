import operator
import unittest
from pyrad.bidict import BiDict


class BiDictTests(unittest.TestCase):
    def setUp(self):
        self.bidict = BiDict()

    def testStartEmpty(self):
        self.assertEqual(len(self.bidict), 0)
        self.assertEqual(len(self.bidict.forward), 0)
        self.assertEqual(len(self.bidict.backward), 0)

    def testLength(self):
        self.assertEqual(len(self.bidict), 0)
        self.bidict.Add("from", "to")
        self.assertEqual(len(self.bidict), 1)
        del self.bidict["from"]
        self.assertEqual(len(self.bidict), 0)

    def testDeletion(self):
        self.assertRaises(KeyError, operator.delitem, self.bidict, "missing")
        self.bidict.Add("missing", "present")
        del self.bidict["missing"]

    def testBackwardDeletion(self):
        self.assertRaises(KeyError, operator.delitem, self.bidict, "missing")
        self.bidict.Add("missing", "present")
        del self.bidict["present"]
        self.assertEqual(self.bidict.HasForward("missing"), False)

    def testForwardAccess(self):
        self.bidict.Add("shake", "vanilla")
        self.bidict.Add("pie", "custard")
        self.assertEqual(self.bidict.HasForward("shake"), True)
        self.assertEqual(self.bidict.GetForward("shake"), "vanilla")
        self.assertEqual(self.bidict.HasForward("pie"), True)
        self.assertEqual(self.bidict.GetForward("pie"), "custard")
        self.assertEqual(self.bidict.HasForward("missing"), False)
        self.assertRaises(KeyError, self.bidict.GetForward, "missing")

    def testBackwardAccess(self):
        self.bidict.Add("shake", "vanilla")
        self.bidict.Add("pie", "custard")
        self.assertEqual(self.bidict.HasBackward("vanilla"), True)
        self.assertEqual(self.bidict.GetBackward("vanilla"), "shake")
        self.assertEqual(self.bidict.HasBackward("missing"), False)
        self.assertRaises(KeyError, self.bidict.GetBackward, "missing")

    def testItemAccessor(self):
        self.bidict.Add("shake", "vanilla")
        self.bidict.Add("pie", "custard")
        self.assertRaises(KeyError, operator.getitem, self.bidict, "missing")
        self.assertEqual(self.bidict["shake"], "vanilla")
        self.assertEqual(self.bidict["pie"], "custard")

    def testRedefinedKey(self):
        self.bidict.Add("Old-Name", 5)
        self.bidict.Add("Old-Name", 6)
        self.assertEqual(self.bidict.GetForward("Old-Name"), 6)
        self.assertEqual(self.bidict.GetBackward(6), "Old-Name")
        self.assertEqual(self.bidict.HasBackward(5), False)
        self.bidict.Add("New-Name", 5)
        del self.bidict["Old-Name"]
        self.assertEqual(self.bidict.forward, {"New-Name": 5})
        self.assertEqual(self.bidict.backward, {5: "New-Name"})

    def testRedefinedKeyKeepsAlias(self):
        self.bidict.Add("Name", 5)
        self.bidict.Add("Alias", 5)
        self.assertEqual(self.bidict.GetBackward(5), "Alias")
        self.bidict.Add("Alias", 6)
        self.assertEqual(self.bidict.GetBackward(5), "Name")
        self.assertEqual(self.bidict.GetBackward(6), "Alias")

    def testAliasDeletion(self):
        self.bidict.Add("Name", 5)
        self.bidict.Add("Alias", 5)
        del self.bidict["Name"]
        self.assertEqual(self.bidict.GetBackward(5), "Alias")
        self.bidict.Add("Name", 5)
        del self.bidict["Name"]
        self.assertEqual(self.bidict.GetBackward(5), "Alias")
        self.assertEqual(self.bidict.GetForward("Alias"), 5)

    def testBackwardDeletionRemovesAliases(self):
        self.bidict.Add("Name", 5)
        self.bidict.Add("Alias", 5)
        self.bidict.Add("Other", 6)
        del self.bidict[5]
        self.assertEqual(self.bidict.forward, {"Other": 6})
        self.assertEqual(self.bidict.backward, {6: "Other"})
