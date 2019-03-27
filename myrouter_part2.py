#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from collections import OrderedDict
class Router(object):
    def __init__(self, net):
        self.net = net
        self.forwarding_table = self.build_forwarding_table()
        self.arp_table={}#store ip addr - [timestamp, MAC] mapping
        self.queue=OrderedDict()
        #for each ip addr, store a list of packets arriving in fifo order, output port, counter for #arp requests has sent so far, timestamp of last use of this entry

    def build_forwarding_table(self):
        forwarding_table = []
        raw_lines = [line.rstrip('\n') for line in open('./forwarding_table.txt')]
        for row in raw_lines:
            temp = row.split()
            forwarding_table.append([IPv4Address(temp[0]),IPv4Address(temp[1]),IPv4Address(temp[2]),temp[3]])
        for intf in self.net.interfaces():
            network_prefix = int(intf.ipaddr) & int(intf.netmask)
            temp = [IPv4Address(network_prefix), intf.netmask, None, intf.name] #the network address, the subnet mask, the next hop address, and the interface
            forwarding_table.append(temp)
        return forwarding_table
    
    def check_queue(self):
        for ip in self.queue:#traverse ordered dict
            if self.queue[ip][2] == 3: #reached 3 requests and no response drop packet give up this entry 
                del queue[ip]
                continue
            if time.time() - self.queue[ip][3] <= 1: #not yet 3 requests and no reply within 1 sec, send a request
                intf = self.queue[ip][1]
                srcMAC = self.net.interface_by_name(intf).ethaddr
                srcIP = self.net.interface_by_name(intf).ipaddr
                destIP = ip
                self.net.send_packet(intf,create_ip_arp_request(srcMAC,srcIP,destIP))
                self.queue[ip][3] = time.time() #update timestamp
                self.queue[ip][2] += 1 #update counter for #arp requests
    
    def lpf_matching(self,ipv4_header):
        max = -1
        matched_result = None
        for entry in self.forwarding_table:
            netaddr = IPv4Network(str(entry[0])+'/'+str(entry[1]))
            if ipv4_header.dst in netaddr:
                if netaddr.prefixlen > max:
                    max = netaddr.prefixlen
                    matched_result = entry
        return matched_result

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()
        my_ips = [intf.ipaddr for intf in my_interfaces]

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
            if gotpkt == False:
                self.check_queue()
            else:
                log_debug("Got a packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                ipv4_h = pkt.get_header(IPv4)
                reply_handled = False
                if arp:
                    srcIP = arp.senderprotoaddr
                    destIP = arp.targetprotoaddr
                    srcMAC = arp.senderhwaddr
                    if arp.operation==ArpOperation.Request:#make a response
                        for intf in my_interfaces:
                            if destIP == intf.ipaddr:
                                self.net.send_packet(intf,create_ip_arp_reply(intf.ethaddr,srcMAC,destIP,srcIP))
                    elif arp.operation==ArpOperation.Reply:#handle arp reply
                        for intf in my_interfaces:
                            if destIP in my_ips:
                                self.arp_table[srcIP] = [srcMAC,time.time()] #add a IP MAC mapping with timestamp (only if targeted @ my device)
                        if srcIP in self.queue:#if the ip is in arp resolution queue
                            out_intf = self.queue[srcIP][1]
                            for packet in self.queue[srcIP][0]:#complete eth header for each packet buffered for this ip and send everything out
                                if not packet[0]:
                                    packet+=Ethernet()
                                packet[0].src = self.net.interface_by_name(out_intf).ethaddr
                                packet[0].dst = srcMAC
                                self.net.send_packet(out_intf,packet)
                            del self.queue[srcIP]#done = delete the entry from queue 
                            reply_handled = True
                self.check_queue()
                if reply_handled == True:#no need to further check ip header of arp reply packet ???
                    continue
                if ipv4_h:
                    ipv4_h.ttl-=1#decrement ttl in header
                    if ipv4_h.dst in my_ips:
                        log_warn("Pkt for me. Drop.")
                        continue
                    #do longest prefix matching in forwarding table
                    matched_entry = self.lpf_matching(ipv4_h)
                    if not matched_entry:#no match, drop packet
                        continue
                    next_hop = matched_entry[2] if matched_entry[2] else ipv4_h.dst#when it is none use destIP of incomming packet itself
                    intf_name = matched_entry[3]
                    if next_hop in self.arp_table:#already have destMAC because of previous request - simple lookup & add eth header & send
                        if not pkt[0]:
                            pkt+=Ethernet()
                        pkt[0].src = self.net.interface_by_name(intf_name).ethaddr
                        pkt[0].dst = self.arp_table[next_hop][0]
                        self.net.send_packet(intf_name,pkt)
                        self.arp_table[next_hop][1] = time.time() #update time of use this arp entry
                    else:#do not have destMAC need arp resolution
                        if next_hop in self.queue:#already have this ip entry in the queue, append an additional packet to its packet list
                            self.queue[next_hop][0].append(pkt)
                        else:#immediately send a request and add this  new  entry to queue
                            srcMAC=self.net.interface_by_name(intf_name).ethaddr
                            srcIP=self.net.interface_by_name(intf_name).ipaddr
                            destIP=next_hop
                            self.net.send_packet(intf_name,create_ip_arp_request(srcMAC,srcIP,destIP))
                            self.queue[next_hop] = [[pkt], intf_name, 1, time.time()]

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()

