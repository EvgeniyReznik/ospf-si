# ospf-si

1. creating virtual eth:
	#create veth0, veth1 and connect them
	1. ip link add veth0 type veth peer name veth1 
	2. ip link set veth0 up
	3. ip link set veth1 up
	4. ip link set veth0 promisc on
	5. ip link set veth1 promisc on

2. connect router to veth0
	1. change SWROPTINS accordingly

3. connect simple_sniffer to veth1 and eth1
	#filter messages from veth1 to eth0
	#pass all messages from eth0 to veth1
	1. sudo python simple_sniffer veth1 eth0
	
