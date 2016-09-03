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



PROTOCOL_OSPF   = 0x59
PROTOCOL_TCP    = 0x06
PROTOCOL_UDP    = 0x11
PROTOCOL_ICMP   = 0x01
PROTOCOL_IGMP   = 0x02

OSPF_HELLO = 0x01

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

        print binascii.hexlify(packet)

    def is_dlep_packet(self, packet):
        # Ethernet Header...
        ethernetHeader = packet[0:14]
        ethrheader = struct.unpack("!6s6s2s", ethernetHeader)
        destinationMAC = binascii.hexlify(ethrheader[0])
        sourceMAC = binascii.hexlify(ethrheader[1])
        protocol = binascii.hexlify(ethrheader[2])

        if protocol == '0800':  # ip4
            # IP Header...
            ipHeader = packet[14:34]
            ipHdr = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ipHeader)
            sizeIP = binascii.hexlify(ipHdr[2])
            protocolIP = binascii.hexlify(ipHdr[6])
            destinationIP = socket.inet_ntoa(ipHdr[9])
            sourceIP = socket.inet_ntoa(ipHdr[8])

            if protocolIP == '0011': #UDP
                icmpHeader = packet[35:42]
                icmpHdr = struct.unpack("!2s2s2s2s", icmpHeader)
                sourcePortUDP = binascii.hexlify(icmpHdr[0])
                destinationPortUDP = binascii.hexlify(icmpHdr[1])
                lengthUDP = binascii.hexlify(icmpHdr[2])
                checksumUDP = binascii.hexlify(icmpHdr[3])
                payloadDataUDP = packet[43:]

                if (sourcePortUDP == "55555" or destinationPortUDP == "55555"):
                    return True

        return False

    def is_ospfv3_packet(self, packet):
        # Ethernet Header...
        ethernetHeader = packet[0:14]
        ethrheader = struct.unpack("!6s6s2s", ethernetHeader)
        destinationMAC = binascii.hexlify(ethrheader[0])
        sourceMAC = binascii.hexlify(ethrheader[1])
        protocol = binascii.hexlify(ethrheader[2])

        if protocol == '86dd':  # ipv6
            #print IP Header...
            ipHeader = packet[14:54]
            ipHdr = struct.unpack("!4s2s1s1s16s16s", ipHeader)
            sizeIP = binascii.hexlify(ipHdr[1])
            protocolIP = binascii.hexlify(ipHdr[2])
            sourceIP = binascii.hexlify(ipHdr[4])
            destinationIP = binascii.hexlify(ipHdr[5])

            if protocolIP == '59': #OSPF
                # print "OSPF packet"
                return True

        return False

    def printStatistics(self):
        if(self.packet_sent_queue % 100 == 0):
            print "ThreadId: ", self.ident
            print " Recv Queue size: ", packet_queue_left.qsize()
            print " Sent Queue size: ", packet_queue_right.qsize()
            print " Packets sent to socket: ", self.packet_sent_socket
            print " Packet sent to queue: ", self.packet_sent_queue

    def async_packet_send(self, socket, packet):
        try:
            socket.send(packet)
            self.packet_sent_socket += 1
            self.printStatistics()
            # print "Packet sent" , self.ident
        except Exception as e:
            print "Packet Bridge: Failed to send!!! ", len(packet)
            print e
            self.print_packet(packet)
        return

    def async_packet_recieve(self, socket):
        global BUFFER_CURRENT_SIZE

        try:
            receivedPacket = socket.recv(1514)
            # print "Recieved packet: ", len(receivedPacket), "ThreadID: ", self.ident
            # self.print_packet(receivedPacket)
            # take care of OSPFv3 packets
            if (self.is_ospfv3_packet(receivedPacket)):
                with self.bufferUpdateLock:
                        # print "buff curr size", BUFFER_CURRENT_SIZE
                        # print "packet size", len(receivedPacket)
                        # check if there is enogh bytes left in epoch
                        if (BUFFER_CURRENT_SIZE >= len(receivedPacket)):
                            self.packet_queue_left.put_nowait(receivedPacket)
                            BUFFER_CURRENT_SIZE -= len(receivedPacket)
                            self.packet_sent_queue += 1
                            self.printStatistics()
                        else:
                            # print "Got to the limit of free epoch bytes"
                            # print "buff curr size", BUFFER_CURRENT_SIZE
                            # print "packet size", len(receivedPacket)
                            None
            # take care of NON OSPFv3 packets
            else:
                self.packet_queue_left.put_nowait(receivedPacket)
                self.packet_sent_queue += 1
                self.printStatistics()
        except Exception as e:
            # print e
            # print "Nothing to recieve!!!"
            None
        return

    def sniff(self):

        rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)  # THIS CODE WORKS
        rawSocket.bind((self.interface_name, ETH_P_ALL))
        rawSocket.setblocking(0)
        print "capture socket recv interface " + self.interface_name

        while True:
            # print "---------------------------------------------bridge packet---------------------------------------------------"

            packet_list_to_send = []
            #get packets out of queue
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

            #send packets from queue
            for packet_to_send in packet_list_to_send:
                self.async_packet_send(rawSocket, packet_to_send)

            #recieve new packet from interface
            self.async_packet_recieve(rawSocket)

            time.sleep(0.0005)

    def __init__(self, bufferUpdateLock, interface_name, packet_queue_left, packet_queue_right):
        Thread.__init__(self)

        self.buffer_current_size = 0
        self.bufferUpdateLock = bufferUpdateLock
        self.interface_name = interface_name
        self.packet_queue_left = packet_queue_left
        self.packet_queue_right = packet_queue_right
        self.packet_sent_socket = 0
        self.packet_sent_queue = 0

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

        print binascii.hexlify(packet)

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
                    print "Packet Bridge: Failed to send!!! ", len(packet_to_send)
                    print e
                    self.print_packet(packet_to_send)
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
    print 'Usage: packet_filter.py host_interface1 host_interface2 buffer_size buffer_refresh_time'
    print ' host_interface1 - active ethernet interface'
    print ' host_interface2 - active ethernet interface'
    print ' buffer_size - size of a buffer in bytes'
    print ' buffer_refresh_time - timer to reset buffer to buffer_size'
    print ' Every time packet gets into bridge, buffer gets smaller according to the packet length'
    print ' Every interval of buffer_refresh_time buffer gets the original size of  buffer_size'
    print ' Packets from interface2 bridged to interface1'
    print ' Packets from interface1 filterd and bridged to interface2'
    print ''
    print 'Example: packet_filter.py veth1 eth0 1024 0.5'
    print '   Sets up a bridge between the hosts connected on veth1 and eth0 with availible bandwidth of 16Kbit/s'


if __name__ == "__main__":

    if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) != 5:
        print len(sys.argv)
        usage()
        sys.exit(-1)

    (host1_interface, host2_interface, buffer_size, buffer_refresh_time) = sys.argv[1:]

    TIME_SLICE = float(buffer_refresh_time)
    BUFFER_SLICE_SIZE = int(buffer_size)

    print TIME_SLICE
    print BUFFER_SLICE_SIZE

    bufferUpdateLock = threading.RLock()
    def bufferSizeUpdate( bufferUpdateLock ):
        global BUFFER_CURRENT_SIZE
        with bufferUpdateLock:
                BUFFER_CURRENT_SIZE = BUFFER_SLICE_SIZE
        # print "Buff Update" , time.ctime()


    timeThread = TimerThread(TIME_SLICE, bufferSizeUpdate, bufferUpdateLock)
    lthread = PacketFilter(bufferUpdateLock, host1_interface, packet_queue_left, packet_queue_right)
    # lthread = PacketBridge(host2_interface, packet_queue_left, packet_queue_right)
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
