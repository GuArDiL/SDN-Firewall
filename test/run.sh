#!/bin/sh
#set -v on
if [ $1 = "firewall" ]; then
	# add path to .pth first
	cd ..
	sudo ryu run firewall.py --observe-link
	cd test
elif [ $1 = "ids" ]; then
	sudo python ../ids_runner.py
elif [ $1 = "mininet" ]; then
	sudo mn --controller=remote,ip=127.0.0.1 --mac --switch ovs,protols=OpenFlow13 --topo single,5 --ipbase=10.0.0.1/24
elif [ $1 = "test1" ]; then
	sudo python dispatcher.py ./pcap/test1.pcap
elif [ $1 = "test2" ]; then
	sudo python dispatcher.py ./pcap/test2-dos.pcap
elif [ $1 = "reset" ]; then
	cp ../rules/firewall.rule.bak ../rules/firewall.rule
	if [ -f "../log/alert.pkt" ]; then
		rm ../log/alert.pkt
	fi
	echo "time,action,label,s_ip,s_port,d_ip,d_port,payload" > ../log/alert.pkt

fi

