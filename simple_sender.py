# !/usr/bin/env python
# import sys, os
import socket
import ospf_hello_packets
from time import sleep

PROTOCOL_OSPF   = 0x59
PROTOCOL_TCP    = 0x06
PROTOCOL_UDP    = 0x11
PROTOCOL_ICMP   = 0x01
PROTOCOL_IGMP   = 0x02

SEND_INTERFACE_NAME = "veth0"
PORT_NUMBER = 1

rawSocketSend = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
rawSocketSend.bind((SEND_INTERFACE_NAME, PORT_NUMBER))

hello_packet = ''
for c in ospf_hello_packets.OSPF_HELLO_PACKET_130.split(' '):
    hello_packet += chr(int(c, 16))


for i in range(0, 1000000, 1):
    rawSocketSend.send(hello_packet)
    print "Sending packet: ", i
    sleep(0.250)
