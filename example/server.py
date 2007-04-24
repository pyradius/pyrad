#!/usr/bin/python

from pyrad import dictionary, packet, server

class FakeServer(server.Server):
	def _HandleAuthPacket(self, fd, pkt):
		server.Server._HandleAuthPacket(self, fd, pkt)

		print "Received an authentication request"
		print "Attributes: "
		for attr in pkt.keys():
			print "%s: %s" % (attr, pkt[attr])
		print

		reply=self.CreateReplyPacket(pkt)
		reply.code=packet.AccessAccept
		self.SendReplyPacket(fd, reply)
	
	def _HandleAcctPacket(self, fd, pkt):
		server.Server._HandleAcctPacket(self, fd, pkt)

		print "Received an accounting request"
		print "Attributes: "
		for attr in pkt.keys():
			print "%s: %s" % (attr, pkt[attr])
		print

		reply=self.CreateReplyPacket(pkt)
		self.SendReplyPacket(fd, reply)


srv=FakeServer(dict=dictionary.Dictionary("dictionary"))
srv.hosts["127.0.0.1"]=server.RemoteHost("127.0.0.1",
	"Kah3choteereethiejeimaeziecumi", "localhost")
srv.BindToAddress("")
srv.Run()
