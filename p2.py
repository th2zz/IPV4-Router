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
        self.forwarding_table = self.build_forwarding_table()

    def build_forwarding_table(self):
        forwarding_table=[]
        file=open("forwarding_table.txt","r")
        for forwarding in file:
            item=forwarding.split()
            forwarding_table.append(item)
        return forwarding_table

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()
        addr = [[intf.ethaddr, intf.ipaddr] for intf in my_interfaces]
        eth = [intf.ethaddr for intf in my_interfaces]
        ip = [intf.ipaddr for intf in my_interfaces]

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
                arp = pkt.get_header(Arp)
                log_debug("My addr: {}".format(addr))
                if arp:
                    for add in addr:
                        if add[1]==arp.targetprotoaddr:
                            self.net.send_packet(dev,create_ip_arp_reply(add[0],arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr))
                            break
                    log_debug("My addr: {}".format(addr))
                    continue

            ####stage 2
            BROADCASTIP=ip_address("255.255.255.255")
            if(pkt.get_header(Ethernet).dst in eth) and (pkt.get_header(IPv4).dst in ip):
                log_debug ("Packet is intended for me")
                continue
            destaddr=pkt.get_header(IPv4).dst
            for entry in self.forwarding_table:
                prefixnet=IPv4Network(entry[0]+"/"+entry[1])
                matches=destaddr in prefixnet
                if (matches):
                    senderhwaddr=pkt.get_header(Ethernet).src
                    senderprotoaddr=pkt.get_header(IPv4).src
                    self.net.send_packet(entry[3],create_ip_arp_request(senderhwaddr,senderprotoaddr,pkt.get_header(IPv4).dst))
                    time.sleep(1)
                    i=0
                    while i<5:
                    ## arp_gotpkt = False
                        try:
                            arp_timestamp, arp_dev, arp_pkt = self.net.recv_packet(timeout=1.0)
                            arp_gotpkt = True
                        except NoPackets:
                            self.net.send_packet(arp_dest, create_ip_arp_request(senderhwaddr, senderprotoaddr,
                                                                                         BROADCASTIP))
                            time.sleep(1)
                            continue
                            if arp_gotpkt:
                                arp = arp_pkt.get_header(Arp)
                                if arp.targethwaddr in myaddr:
                                    targethwaddr = arp.senderhwaddr
                                    self.net.send_packet(targethwaddr, pkt)
                                    break
                        i+=1

            if (matches):
                continue
            
def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
