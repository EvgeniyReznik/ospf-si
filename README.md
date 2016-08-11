# ospf-si

### 1. creating virtual eth:
	* "create veth0, veth1 and connect them"
	1. sudo ip link add veth0 type veth peer name veth1 
	2. sudo ip link set veth0 up
	3. sudo ip link set veth1 up
	4. sudo ip link set veth0 promisc on
	5. sudo ip link set veth1 promisc on

### 2. connect router to veth0
	1. change SWROPTINS accordingly

### 3. connect packet filter to veth1 and eth0
	* "filter messages from veth1 to eth0"
	* "pass all messages from eth0 to veth1"
	1. sudo python packet_filter.py veth1 eth0
	
