from optparse import OptionParser
from scapy.all import *
from threading import Thread
from struct import pack, unpack
from time import sleep

def sp_byte(val):
    return pack("<B", val)

def su_nint(str):
    return unpack(">I", str)[0]

def ipn2num(ipn):
    """ipn(etwork) is BE dotted string ip address
    """
    if ipn.count(".") != 3:
        print("ipn2num warning: string < %s > is not proper dotted IP address" % ipn)

    return su_nint( "".join([sp_byte(int(p)) for p in ipn.strip().split(".")]))

def get_route_if(iface):
    try:
        return [route for route in conf.route.routes if route[3] == iface and route[2] == "0.0.0.0"][0]
    except IndexError:
        print("Interface '%s' has no ip address configured or link is down?" % (iface));
        return None;

class PacketCapture(Thread):

    def __init__(self, net, nm, recv_iface, send_iface):
        Thread.__init__(self)

        self.net = net
        self.netmask = nm
        self.recv_iface = recv_iface
        self.send_iface = send_iface
        self.recv_mac = get_if_hwaddr(recv_iface)
        self.send_mac = get_if_hwaddr(send_iface)
        self.filter = "ether dst %s and ip" % self.recv_mac
        self.arp_cache = []

        self.name = "PacketCapture(%s on %s)" % (self.name, self.recv_iface)

        self.fw_count = 0

    def run(self):

        print("%s: waiting packets (%s) on interface %s" % (self.name, self.filter, self.recv_iface))

        sniff(count = 0,  prn = self.process, store = 0, filter = self.filter, iface = self.recv_iface)

    def process(self, pkt):

        # only bridge IP packets
        if pkt.haslayer(Ether) and pkt.haslayer(IP):

            dst_n = ipn2num(pkt[IP].dst)

            if dst_n & self.netmask != self.net:
                # don't forward if the destination ip address
                # doesn't match the destination network address
                return

            # update layer 2 addresses
            rmac = self.get_remote_mac(pkt[IP].dst)
            if rmac == None:
                print("%s: packet not forwarded %s %s -) %s %s" % (self.name, pkt[Ether].src, pkt[IP].src, pkt[Ether].dst, pkt[IP].dst))
                return

            pkt[Ether].src = self.send_mac
            pkt[Ether].dst = rmac

            #print("%s: forwarding %s %s -> %s %s" % (self.name, pkt[Ether].src, pkt[IP].src, pkt[Ether].dst, pkt[IP].dst))

            sendp(pkt, iface = self.send_iface)

            self.fw_count += 1

    def get_remote_mac(self, ip):

        mac = ""

        for m in self.arp_cache:
            if m["ip"] == ip and m["mac"]:
                return m["mac"]

        mac = getmacbyip(ip)
        if mac == None:
            print("%s: Could not resolve mac address for destination ip address %s" % (self.name, ip))
        else:
            self.arp_cache.append({"ip": ip, "mac": mac})

        return mac

    def stop(self):
        Thread._Thread__stop(self)
        print("%s stopped" % self.name)


if __name__ == "__main__":
    parser = OptionParser(description = "Bridge packets", prog = "brscapy", usage = "Usage: brscapy -l <intf> (--left= <intf>) -r <inft> (--right=<intf>)")
    parser.add_option("-l", "--left",  action = "store", dest = "left",  default = None, choices = get_if_list(), help = "Left side network interface of the bridge")
    parser.add_option("-r", "--right", action = "store", dest = "right", default = None, choices = get_if_list(), help = "Right side network interface of the bridge")

    args, opts = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    lif = args.left
    rif = args.right

    lroute = get_route_if(lif)
    rroute = get_route_if(rif)

    if (lroute == None or rroute == None):
        print("Invalid ip addressing on given interfaces");
        exit(1)

    if (len(lroute) != 5 or len(rroute) != 5):
        print("Invalid scapy routes")
        exit(1)

    conf.verb = 0

    lthread = PacketCapture(rroute[0], rroute[1], lif, rif)
    rthread = PacketCapture(lroute[0], lroute[1], rif, lif)

    lthread.start()
    rthread.start()

    try:
        while True:
            sys.stdout.write("FORWARD count: [%s -> %s  %d] [%s <- %s  %d]\r" % (lif, rif, lthread.fw_count, lif, rif, rthread.fw_count))
            sys.stdout.flush()
            sleep(0.1)
    except KeyboardInterrupt:
        pass

    lthread.stop()
    rthread.stop()