# !/usr/bin/env python
# import sys, os
import socket
import example_packets
from time import sleep

PROTOCOL_OSPF   = 0x59
PROTOCOL_TCP    = 0x06
PROTOCOL_UDP    = 0x11
PROTOCOL_ICMP   = 0x01
PROTOCOL_IGMP   = 0x02

SEND_INTERFACE_NAME = "ens33"
PORT_NUMBER = 1

rawSocketSend = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
rawSocketSend.bind((SEND_INTERFACE_NAME, PORT_NUMBER))

hello_packet_130 = ''
for c in example_packets.OSPF_HELLO_PACKET_130.split(' '):
    hello_packet_130 += chr(int(c, 16))

hello_packet_310 = ''
for c in example_packets.OSPF_HELLO_PACKET_310.split(' '):
    hello_packet_310 += chr(int(c, 16))

ipv4_ping_request_packet = ''
for c in example_packets.IPV4_PING_REQUEST_PACKET.split(' '):
    ipv4_ping_request_packet += chr(int(c, 16))

ipv4_ping_reply_packet = ''
for c in example_packets.IPV4_PING_REPLY_PACKET.split(' '):
    ipv4_ping_reply_packet += chr(int(c, 16))


for i in range(0, 1000000, 1):
    rawSocketSend.send(ipv4_ping_request_packet)
    for j in range(0, 10, 1):
        rawSocketSend.send(hello_packet_130)
        # print "Sending packet: ", i
        sleep(0.125)
    rawSocketSend.send(ipv4_ping_reply_packet)
    for j in range(0, 10, 1):
        rawSocketSend.send(hello_packet_310)
        # print "Sending packet: ", j
        sleep(0.125)
    rawSocketSend.send(ipv4_ping_request_packet)
