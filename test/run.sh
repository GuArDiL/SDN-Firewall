#!/bin/sh
#set -v on
if [ $1 = "firewall" ]; then
	# add path to .pth first
	sudo ryu run firewall.py --observe-links --verbose
elif [ $1 = "ids" ]; then
	sudo python ../ids_runner.py
elif [ $1 = "mininet" ]; then
	sudo mn --controller=remote,ip=127.0.0.1 --mac --switch ovs,protols=OpenFlow13 --topo single,5 --ipbase=10.0.0.1/24
elif [ $1 = "test" ]; then
	sudo python ./dispatcher.py
fi

