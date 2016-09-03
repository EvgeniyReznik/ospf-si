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

SEND_INTERFACE_NAME = "veth0"
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

ipv4_dlep_src_packet = ''
for c in example_packets.IPV4_DLEP_SRC_PACKET.split(' '):
    ipv4_dlep_src_packet += chr(int(c, 16))

ipv4_dlep_dst_packet = ''
for c in example_packets.IPV4_DLEP_DST_PACKET.split(' '):
    ipv4_dlep_dst_packet += chr(int(c, 16))


for i in range(0, 1000000, 1):
    for j in range(0, 10, 1):
        rawSocketSend.send(hello_packet_130)
        rawSocketSend.send(ipv4_dlep_dst_packet)
        rawSocketSend.send(ipv4_dlep_src_packet)
        rawSocketSend.send(ipv4_ping_request_packet)
        # print "Sending packet: ", i
        sleep(0.125)

    for j in range(0, 10, 1):
        rawSocketSend.send(ipv4_dlep_dst_packet)
        rawSocketSend.send(ipv4_dlep_src_packet)
        rawSocketSend.send(ipv4_ping_reply_packet)
        rawSocketSend.send(hello_packet_310)
        # print "Sending packet: ", j
        sleep(0.125)
