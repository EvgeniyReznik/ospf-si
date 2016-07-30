# !/usr/bin/env python
import struct
# import sys, os
import socket
import binascii
import IN
import netaddr
import time


PROTOCOL_OSPF   = 0x59
PROTOCOL_TCP    = 0x06
PROTOCOL_UDP    = 0x11
PROTOCOL_ICMP   = 0x01
PROTOCOL_IGMP   = 0x02

OSPF_HELLO = 0x01


RECV_INTERFACE_NAME = "veth1"
SEND_INTERFACE_NAME = "ens33"
PORT_NUMBER = 0
ETH_P_ALL = 3

# rawSocketRecv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) #THIS CODE WORKS
# rawSocketRecv.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, struct.pack("%ds"%(len("veth1")+1,),"veth1"))

rawSocketRecv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)  #THIS CODE WORKS
rawSocketRecv.bind((RECV_INTERFACE_NAME, ETH_P_ALL))

rawSocketSend = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rawSocketSend.bind((SEND_INTERFACE_NAME, PORT_NUMBER))

HOP_TIME = 10  # number of seconds
hopStart = time.time()
sizeIP =1500

for i in range(0, 1000, 1):
    # print "---------------------------------------------packet---------------------------------------------------"
    receivedPacket = rawSocketRecv.recv(2048)

    # Ethernet Header...
    ethernetHeader = receivedPacket[0:14]
    ethrheader = struct.unpack("!6s6s2s", ethernetHeader)
    destinationIP = binascii.hexlify(ethrheader[0])
    sourceIP = binascii.hexlify(ethrheader[1])
    protocol = binascii.hexlify(ethrheader[2])

    # print "Destination: " + destinationIP
    # print "Source: " + sourceIP
    # print "Protocol: " + protocol

    if protocol == '0800':  # ip4
        # IP Header...
        ipHeader = receivedPacket[14:34]
        ipHdr = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ipHeader)
        sizeIP = binascii.hexlify(ipHdr[2])
        protocolIP = binascii.hexlify(ipHdr[6])
        destinationIP = socket.inet_ntoa(ipHdr[9])
        sourceIP = socket.inet_ntoa(ipHdr[8])
        # print "Source IP: " + sourceIP
        # print "Destination IP: " + destinationIP
        # print "Protocol IP: " + protocolIP
        # print "Size IP: " + str(int(sizeIP, 16))

    if protocol == '86dd': #ip6
        # print 'ipv6 packet'
        # IP Header...
        ipHeader = receivedPacket[14:54]
        ipHdr = struct.unpack("!4s2s1s1s16s16s", ipHeader)
        sizeIP = binascii.hexlify(ipHdr[1])
        protocolIP = binascii.hexlify(ipHdr[2])
        sourceIP = binascii.hexlify(ipHdr[4])
        destinationIP = binascii.hexlify(ipHdr[5])
        # print "Source IP: " + sourceIP
        # print "Destination IP: " + destinationIP
        # print "Protocol IP: " + protocolIP
        # print "Size IP: " + str(int(sizeIP, 16))

        if protocolIP == '59': #OSPF protocol
            # print "OSPF"
            ospfBasicHeader = receivedPacket[54:70]
            ospfBasicHdr = struct.unpack("!1s1s2s4s4s2s2s", ospfBasicHeader)
            typeOSPF = binascii.hexlify(ospfBasicHdr[1])
            # print "OSPF TYPE: " + typeOSPF

            if typeOSPF == '01': #OSPF HELLO
                # print "OSPF HELLO"
                if (time.time() < hopStart + HOP_TIME):
                    continue
                hopStart = time.time()
        # else:
            # print "DATA"

    if int(sizeIP, 16) < 1500:
        rawSocketSend.send(receivedPacket)
        # print "Packet sent"
