#!/usr/bin/env python
# coding: utf-8

from __future__ import unicode_literals

import sys
import six
from twisted.internet import reactor
from twisted.python import log
from pyrad import curved, dictionary, server


class RADIUSAccountingProtocol(curved.RADIUSAccounting, object):
    def __init__(self, hosts, rad_dict):
        super(RADIUSAccountingProtocol, self).__init__(hosts, rad_dict)

    def processPacket(self, pkt):
        super(RADIUSAccountingProtocol, self).processPacket(pkt)

        if not pkt.VerifyAcctRequest():
            raise curved.PacketError('Authentication failed')

        log.msg("Received {} from {} ({})".format(
            pkt[b'Acct-Status-Type'][0],
            pkt.source[0],
            pkt[b'Acct-Session-Id'][0])
        )

        reply = self.createReplyPacket(pkt)
        self.transport.write(reply.ReplyPacket(), reply.source)


if __name__ == '__main__':
    log.startLogging(sys.stdout, 0)
    reactor.listenUDP(1813, RADIUSAccountingProtocol(
        hosts={
            '192.168.1.11': server.RemoteHost('192.168.1.11',
                                              six.b(b'testsecret'),
                                              "AP11"),
            '192.168.1.12': server.RemoteHost('192.168.1.12',
                                              six.b(b'testsecret'),
                                              "AP12"),
        },
        rad_dict=dictionary.Dictionary('dictionary'))
    )
    reactor.run()
