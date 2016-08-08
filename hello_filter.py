# !/usr/bin/env python
import struct
import sys
import socket
import binascii
from threading import Thread
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


class PacketFilter(Thread):

    def sniff(self):

        rawSocketRecv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)  # THIS CODE WORKS
        rawSocketRecv.bind((self.recv_iface, ETH_P_ALL))
        print "capture socket recv interface " + self.recv_iface

        rawSocketSend = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        rawSocketSend.bind((self.send_iface, ETH_P_ALL))
        print "capture socket send interface " + self.send_iface

        HOP_TIME_SAME_PACKET = 10  # number of seconds
        HOP_TIME_DIFF_PACKET = 5   # number of seconds
        hopStart = time.time()
        sizeIP = '0x00'

        while True:
            # print "---------------------------------------------capture packet---------------------------------------------------"
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

            if protocol == '86dd':  # ip6
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

                if protocolIP == '59':  # OSPF protocol
                    # print "OSPF"
                    ospfBasicHeader = receivedPacket[54:70]
                    ospfBasicHdr = struct.unpack("!1s1s2s4s4s2s2s", ospfBasicHeader)
                    typeOSPF = binascii.hexlify(ospfBasicHdr[1])
                    # print "OSPF TYPE: " + typeOSPF

                    if typeOSPF == '01':  # OSPF HELLO
                        # print "OSPF HELLO"
                        if (receivedPacket == self.ospf_hello_cache):
                            #same ospf hello packet as previous
                            if (time.time() < hopStart + HOP_TIME_SAME_PACKET):
                                #do not send packet if it didnt change and 10 sec didnt pass
                                continue
                            hopStart = time.time()
                        else:
                            #ospf hello packet deffers from previous
                            self.ospf_hello_cache = receivedPacket
                            if (time.time() < hopStart + HOP_TIME_DIFF_PACKET):
                                #do not send packet if it didnt change and 10 sec didnt pass
                                continue
                            hopStart = time.time()

            if int(sizeIP, 16) < 1500:
                try:
                    rawSocketSend.send(receivedPacket)
                    # print "Packet sent"
                except:
                    print "Packet Filter: Packet dropped!!!"
                    continue

    def __init__(self, recv_iface, send_iface):
        Thread.__init__(self)

        self.ospf_hello_cache = None
        self.recv_iface = recv_iface
        self.send_iface = send_iface

    def run(self):
        self.sniff()

    def stop(self):
        Thread._Thread__stop(self)
        print("%s stopped" % self.name)


class PacketBridge(Thread):

    def sniff(self):

        rawSocketRecv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)  # THIS CODE WORKS
        rawSocketRecv.bind((self.recv_iface, ETH_P_ALL))
        print "bridge socket recv interface " + self.recv_iface

        rawSocketSend = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        rawSocketSend.bind((self.send_iface, ETH_P_ALL))
        print "bridge socket send interface " + self.send_iface

        while True:
            # print "---------------------------------------------bridge packet---------------------------------------------------"
            receivedPacket = rawSocketRecv.recv(2048)
            try:
                rawSocketSend.send(receivedPacket)
                # print "Packet sent"
            except:
                print "Packet Bridge: Packet dropped!!!"
                continue

    def __init__(self, recv_iface, send_iface):
        Thread.__init__(self)
        self.recv_iface = recv_iface
        self.send_iface = send_iface

    def run(self):
        self.sniff()

    def stop(self):
        Thread._Thread__stop(self)
        print("%s stopped" % self.name)

def usage():
    print 'Usage: hello_filter.py host1_interface host2_interfcae'
    print ''
    print 'Example: hello_filter.py veth1 eth0'
    print '   Sets up a bridge between the hosts connected on veth1 and eth0'


if __name__ == "__main__":

    # if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) != 3:
    #     usage()
    #     sys.exit(-1)
    #
    # (host1_interface, host2_interface) = sys.argv[1:]

    host1_interface = RECV_INTERFACE_NAME
    host2_interface = SEND_INTERFACE_NAME

    lthread = PacketFilter(host1_interface, host2_interface)
    rthread = PacketBridge(host2_interface, host1_interface)

    lthread.start()
    rthread.start()

    try:
        while True:
            sys.stdout.flush()
            time.sleep(0.250)
    except KeyboardInterrupt:
        pass

    lthread.stop()
    rthread.stop()