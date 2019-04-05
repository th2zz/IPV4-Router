#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                arp_table={}
                arp = pkt.get_header(Arp)
                if arp:
                    srcIP = arp.senderprotoaddr
                    destIP = arp.targetprotoaddr
                    srcMAC = arp.senderhwaddr
                    my_interfaces = self.net.interfaces()
                    if arp.operation==ArpOperation.Request:
                        for intf in my_interfaces:
                            if destIP == intf.ipaddr:
                                reply_pkt = create_ip_arp_reply(intf.ethaddr,srcMAC,destIP,srcIP)
                                self.net.send_packet(intf,reply_pkt)#send arp reply for the request
                    elif arp.operation==ArpOperation.Reply:
                        for intf in my_interfaces:
                            if destIP == intf.ipaddr:
                                arp_table[srcIP] = srcMAC #add a mapping
def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
