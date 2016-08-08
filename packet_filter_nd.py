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

    def sniff(self):


        while True:
            # print "---------------------------------------------bridge packet---------------------------------------------------"
            receivedPacket = self.left_socket.recv(2048)

            # Ethernet Header...
            ethernetHeader = receivedPacket[0:14]
            ethrheader = struct.unpack("!6s6s2s", ethernetHeader)
            destinationMAC = binascii.hexlify(ethrheader[0])
            sourceMAC = binascii.hexlify(ethrheader[1])
            protocol = binascii.hexlify(ethrheader[2])

            try:
                self.right_socket.send(receivedPacket)
                # print "Packet sent"
            except:
                print "Packet Bridge: Packet dropped!!!"
                continue

    def __init__(self, left_socket, right_socket):
        Thread.__init__(self)
        self.left_socket = left_socket
        self.right_socket = right_socket

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

    bufferUpdateLock = threading.RLock()
    def bufferSizeUpdate( bufferUpdateLock ):
        global BUFFER_CURRENT_SIZE
        with bufferUpdateLock:
                BUFFER_CURRENT_SIZE = BUFFER_SLICE_SIZE
        print "Buff Update" , time.ctime()


    rawSocketRecv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)  # THIS CODE WORKS
    rawSocketRecv.bind((host1_interface, ETH_P_ALL))
    print "capture socket recv interface " + host1_interface

    rawSocketSend = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    rawSocketSend.bind((host2_interface, ETH_P_ALL))
    print "capture socket send interface " + host2_interface

    timeThread = TimerThread(TIME_SLICE, bufferSizeUpdate, bufferUpdateLock)
    lthread = PacketFilter(bufferUpdateLock, rawSocketRecv, rawSocketSend)
    rthread = PacketBridge(rawSocketSend, rawSocketRecv)

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
