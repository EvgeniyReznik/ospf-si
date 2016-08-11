# !/usr/bin/env python
import struct
import sys
import socket
import binascii
from threading import Thread
import threading
from threading import Event
import time
from sys import getsizeof
import  Queue


TIME_SLICE = 0.5
BUFFER_SLICE_SIZE = 1024


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

packet_queue_left = Queue.Queue()
packet_queue_right = Queue.Queue()

# rawSocketRecv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) #THIS CODE WORKS
# rawSocketRecv.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, struct.pack("%ds"%(len("veth1")+1,),"veth1"))


class TimerThread(Thread):
    def __init__(self, timeSlice, timeFunc, param):
        Thread.__init__(self)

        self.timeSlice = timeSlice
        self.timeFunc = timeFunc
        self.param = param

    def periodicaly(self):
        while True:
            self.timeFunc(self.param)
            time.sleep(self.timeSlice)

    def run(self):
        self.periodicaly()

    def stop(self):
        Thread._Thread__stop(self)
        print("%s stopped" % self.name)


class PacketFilter(Thread):

    def sniff(self):

        global BUFFER_CURRENT_SIZE

        sizeIP = '0x00'

        while True:
            # print "---------------------------------------------capture packet---------------------------------------------------"
            receivedPacket = self.left_socket.recv(2048)

            # Ethernet Header...
            ethernetHeader = receivedPacket[0:14]
            ethrheader = struct.unpack("!6s6s2s", ethernetHeader)
            destinationMAC = binascii.hexlify(ethrheader[0])
            sourceMAC = binascii.hexlify(ethrheader[1])
            protocol = binascii.hexlify(ethrheader[2])

            #check if there is enogh bytes left in epoch
            with self.bufferUpdateLock:
                print "buff curr size" , BUFFER_CURRENT_SIZE
                print "packet size" , len(receivedPacket)
                if (BUFFER_CURRENT_SIZE >= len(receivedPacket)):
                    BUFFER_CURRENT_SIZE -= len(receivedPacket)
                    if int(sizeIP, 16) < 1500:
                        try:
                            self.right_socket.send(receivedPacket)
                            print "Packet sent"
                        except:
                            print "Packet Filter: Packet dropped!!!"
                            continue
                else:
                    print "Got to the limit of free epoch bytes"
                    continue

    def __init__(self, bufferUpdateLock, left_socket, right_socket):
        Thread.__init__(self)

        self.buffer_current_size = 0
        self.bufferUpdateLock = bufferUpdateLock
        self.left_socket = left_socket
        self.right_socket = right_socket

    def run(self):
        self.sniff()

    def stop(self):
        Thread._Thread__stop(self)
        print("%s stopped" % self.name)


class PacketBridge(Thread):

    def print_packet(self, packet):
        # Ethernet Header...
        ethernetHeader = packet[0:14]
        ethrheader = struct.unpack("!6s6s2s", ethernetHeader)
        destinationMAC = binascii.hexlify(ethrheader[0])
        sourceMAC = binascii.hexlify(ethrheader[1])
        protocol = binascii.hexlify(ethrheader[2])

        print "DestinationMAC: " + destinationMAC
        print "SourceMAC: " + sourceMAC
        print "Protocol: " + protocol

        if protocol == '0800':  # ip4
            # IP Header...
            ipHeader = packet[14:34]
            ipHdr = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ipHeader)
            sizeIP = binascii.hexlify(ipHdr[2])
            protocolIP = binascii.hexlify(ipHdr[6])
            destinationIP = socket.inet_ntoa(ipHdr[9])
            sourceIP = socket.inet_ntoa(ipHdr[8])
            print "Source IP: " + sourceIP
            print "Destination IP: " + destinationIP
            print "Protocol IP: " + protocolIP
            print "Size IP: " + str(int(sizeIP, 16))

            if protocolIP == '0001':
                print "ICMP"
                icmpHeader = packet[35:42]
                icmpHdr = struct.unpack("!1s1s2s4s", icmpHeader)
                typeOfMessageICMP = binascii.hexlify(icmpHdr[0])
                codeICMP = binascii.hexlify(icmpHdr[1])
                checksumICMP = binascii.hexlify(icmpHdr[2])
                headerDataICMP = binascii.hexlify(icmpHdr[3])
                payloadDataICMP = packet[43:]
                print "Type Of Message: " + typeOfMessageICMP
                print "Code: " + codeICMP
                print "Checksum: " + checksumICMP
                print "Header Data: " + headerDataICMP
                print "Payload Data: " + payloadDataICMP

        if protocol == '86dd':  # ip6
            print 'ipv6 packet'
            # IP Header...
            ipHeader = packet[14:54]
            ipHdr = struct.unpack("!4s2s1s1s16s16s", ipHeader)
            sizeIP = binascii.hexlify(ipHdr[1])
            protocolIP = binascii.hexlify(ipHdr[2])
            sourceIP = binascii.hexlify(ipHdr[4])
            destinationIP = binascii.hexlify(ipHdr[5])
            print "Source IP: " + sourceIP
            print "Destination IP: " + destinationIP
            print "Protocol IP: " + protocolIP
            print "Size IP: " + str(int(sizeIP, 16))

    def printStatistics(self):
        if(self.packet_sent_queue % 100 == 0):
            print "ThreadId: ", self.ident
            print " Recv Queue size: ", packet_queue_left.qsize()
            print " Sent Queue size: ", packet_queue_right.qsize()
            print " Packets sent to socket: ", self.packet_sent_socket
            print " Packet sent to queue: ", self.packet_sent_queue

    def sniff(self):
        rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)  # THIS CODE WORKS
        rawSocket.bind((self.interface_name, ETH_P_ALL))
        rawSocket.setblocking(0)
        print "capture socket recv interface " + self.interface_name

        while True:
            # print "---------------------------------------------bridge packet---------------------------------------------------"

            packet_list_to_send = []
            while(True):
                try:
                    packet_temp = None
                    packet_temp = self.packet_queue_right.get_nowait()
                    if (packet_temp != None):
                        packet_list_to_send.append(packet_temp)
                except Exception as e:
                    # print "No packets to send!!!"
                    # print e
                    break

            for packet_to_send in packet_list_to_send:
                try:
                    rawSocket.send(packet_to_send)
                    self.packet_sent_socket += 1
                    self.printStatistics()
                    # print "Packet sent" , self.ident
                except Exception as e:
                    # print "Packet Bridge: Packet dropped!!!"
                    # print e
                    # self.print_packet(packet_to_send)
                    continue

            try:
                receivedPacket = rawSocket.recv(8192)
                # print "Recieved packet: ", len(receivedPacket), "ThreadID: ", self.ident
                # self.print_packet(receivedPacket)
                self.packet_queue_left.put_nowait(receivedPacket)
                self.packet_sent_queue += 1
                self.printStatistics()
            except Exception as e:
                # print e
                # print "Nothing to recieve!!!"
                None

            time.sleep(0.001)

    def __init__(self, interface_name, packet_queue_left, packet_queue_right):
        Thread.__init__(self)
        self.interface_name = interface_name
        self.packet_queue_left = packet_queue_left
        self.packet_queue_right = packet_queue_right
        self.packet_sent_socket = 0
        self.packet_sent_queue = 0

    def run(self):
        print "Strted thread: ", self.ident
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

    bufferUpdateLock = threading.RLock()
    def bufferSizeUpdate( bufferUpdateLock ):
        global BUFFER_CURRENT_SIZE
        with bufferUpdateLock:
                BUFFER_CURRENT_SIZE = BUFFER_SLICE_SIZE
        # print "Buff Update" , time.ctime()


    timeThread = TimerThread(TIME_SLICE, bufferSizeUpdate, bufferUpdateLock)
    # lthread = PacketFilter(bufferUpdateLock, rawSocketRecv, rawSocketSend)
    lthread = PacketBridge(host1_interface, packet_queue_left, packet_queue_right)
    rthread = PacketBridge(host2_interface, packet_queue_right, packet_queue_left)

    timeThread.start()
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
    timeThread.stop()
