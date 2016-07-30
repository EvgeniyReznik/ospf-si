#!/usr/bin/python2

import sys
import signal
from threading import Thread,Lock
from scapy.all import sniff,IP,sendp,srp1,Ether,ARP,get_if_list,get_if_hwaddr


def usage():
    print 'Usage: scapy_throuput.py host1_interface host1_ip host2_interfcae host2_ip'
    print ''
    print 'Example: sudo python scapy_throuput.py eth1 10.1.1.1 eth2 10.1.2.2'
    print '   Sets up a bridge between the hosts connected on eth1 and eth2'
    print '   with ips 10.1.1.1 and 10.1.2.2, respectively.'

class Sniffer():
    pktcnt = 0

    def discover_mac_address(self, ip, interface):
        "Figures out MAC address for given IP"
        print 'trying to get MAC address of ' + ip
        # arp ping
        p = srp1(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), iface=interface)
        print 'got ' + p[ARP].hwsrc
        return p[ARP].hwsrc

    def __init__(self, input_interface, output_interface, dest_ip, sniffer_name):
        self.input_interface = input_interface
        self.output_interface = output_interface
        self.dest_ip = dest_ip
        self.sniffer_name = sniffer_name

        self.dest_mac_address = self.discover_mac_address(self.dest_ip, self.output_interface)

        self.my_macs = [get_if_hwaddr(i) for i in get_if_list()]
        self.output_mac = get_if_hwaddr(self.output_interface)

    def process_packet(self, pkt):
        # ignore packets that were sent from one of our own interfaces
        if pkt[Ether].src in self.my_macs:
            return

        self.pktcnt += 1
        p = pkt.copy()
        forwardtxt = []
        # if this packet has an IP layer, change the dst field
        # to our final destination
        if IP in p:
            forwardtxt.append( 'changing IP %s -> %s' % (p[IP].dst, self.dest_ip) )
            p[IP].dst = self.dest_ip

        # if this packet has an ethernet layer, change the dst field
        # to our final destination. We have to worry about this since
        # we're using sendp (rather than send) to send the packet.  We
        # also don't fiddle with it if it's a broadcast address.
        if Ether in p \
           and p[Ether].dst != 'ff:ff:ff:ff:ff:ff':
            forwardtxt.append( 'changing MAC dst %s -> %s' % (p[Ether].dst, self.dest_mac_address) )
            p[Ether].dst = self.dest_mac_address
            # forwardtxt.append( 'changing MAC src %s -> %s' % (p[Ether].src, self.output_mac) )
            # p[Ether].src = self.output_mac

        send(p, iface=self.output_interface)
        return "==============\n" \
               + " ".join([self.sniffer_name] + forwardtxt) \
               + "\n=============="

    def stopper_check(self, pkt):
        return not still_running_lock.locked()

    def sniffloop(self):
        sniff(iface=self.input_interface, prn=self.process_packet, stop_filter=self.stopper_check)

# global list of running threads
threads = []
# global lock to signal that we're still running
still_running_lock = Lock()

# catch Ctl-c and clean up threads
def signal_handler(signal, frame):
    print 'Cleaning up sniff threads...'
    still_running_lock.release()
    try:
        for t in threads: t.join()
    except:
        pass
    print 'exiting.'
    sys.exit(0)

if __name__ == '__main__':
    if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) != 5:
        usage()
        sys.exit(-1)

    (host1_interface, host1_ip, host2_interface, host2_ip) = sys.argv[1:]

    sniffer1 = Sniffer(host1_interface, host2_interface, host2_ip, 'TO')
    sniffer2 = Sniffer(host2_interface, host1_interface, host1_ip, 'FROM')

    threads.append( Thread(target=sniffer1.sniffloop) )
    threads.append( Thread(target=sniffer2.sniffloop) )

    # set our "state" to running by acquiring the lock
    still_running_lock.acquire()

    for t in threads: t.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()