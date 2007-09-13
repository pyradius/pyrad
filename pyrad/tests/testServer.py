import unittest
from pyrad.server import RemoteHost
from pyrad.server import Server

class RemoteHostTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host=RemoteHost("address", "secret", "name", "authport", "acctport")
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")


    def testNamedConstruction(self):
        host=RemoteHost(address="address", secret="secret", name="name",
               authport="authport", acctport="acctport")
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")


class ServerConstructiontests(unittest.TestCase):
    def testSimpleConstruction(self):
        server=Server()
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, 1812)
        self.assertEqual(server.acctport, 1813)
        self.assertEqual(server.hosts, {})


    def testParameterOrder(self):
        server=Server([], "authport", "acctport", "hosts", "dict")
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, "authport")
        self.assertEqual(server.acctport, "acctport")
        self.assertEqual(server.dict, "dict")


    def testBindDuringConstruction(self):
        def BindToAddress(self, addr):
            self.bound=addr
        bta=Server.BindToAddress
        Server.BindToAddress=BindToAddress

        server=Server(["one", "two", "three"])
        self.assertEqual(server.bound, ["one", "two", "three"])

        Server.BindToAddress=btoa


