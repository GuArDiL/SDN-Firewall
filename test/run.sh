#!/bin/sh
#set -v on

SDN_FIREWALL_ROOT=$(dirname $(readlink -f "$0"))"/../"

FILE_IDS_RUNNER=$SDN_FIREWALL_ROOT"ids_runner.py"
FILE_DISPATCHER=$SDN_FIREWALL_ROOT"test/dispatcher.py"
FILE_TEST1_PCAP=$SDN_FIREWALL_ROOT"test/pcap/test1.pcap"
FILE_TEST2_PCAP=$SDN_FIREWALL_ROOT"test/pcap/test2-Generic2.pcap"

FILE_PACKET_LOG=$SDN_FIREWALL_ROOT"log/pkt.all"
FILE_FIREWALL_LOG=$SDN_FIREWALL_ROOT"log/firewall.log"
FILE_IDS_LOG=$SDN_FIREWALL_ROOT"log/ids.log"
FILE_ADMIN_LOG=$SDN_FIREWALL_ROOT"log/admin.log"
FILE_EVENT_IMPORTANT=$SDN_FIREWALL_ROOT"log/event.important"
FILE_START_TIME=$SDN_FIREWALL_ROOT"log/start.time"

FILE_FIREWALL_RULE=$SDN_FIREWALL_ROOT"rules/firewall.rule"
FILE_FIREWALL_RULE_BAK=$SDN_FIREWALL_ROOT"rules/firewall.rule.bak"
FILE_IDS_RULE=$SDN_FIREWALL_ROOT"rules/ids.rule"
FILE_IDS_RULE_BAK=$SDN_FIREWALL_ROOT"rules/ids.rule.bak"

if [ $1 = "firewall" ]; then
	# add path to .pth first
	cd ..
	sudo ryu run ofctl_rest.py firewall.py --observe-link
	cd test
elif [ $1 = "ids" ]; then
	sudo python $FILE_IDS_RUNNER
elif [ $1 = "mininet" ]; then
	sudo mn --controller=remote,ip=127.0.0.1 --mac --switch ovs,protols=OpenFlow13 --topo single,5 --ipbase=10.0.0.1/24
elif [ $1 = "admin" ]; then
	cd ../../web_admin
	sudo python manage.py runserver 0.0.0.0:8192 --noreload
	cd $SDN_FIREWALL_ROOT"test/"
elif [ $1 = "test1" ]; then
	sudo python $FILE_DISPATCHER $FILE_TEST1_PCAP
elif [ $1 = "test2" ]; then
	sudo python $FILE_DISPATCHER $FILE_TEST2_PCAP
elif [ $1 = "reset" ]; then
	cp $FILE_FIREWALL_RULE_BAK $FILE_FIREWALL_RULE 
	cp $FILE_IDS_RULE_BAK $FILE_IDS_RULE

	echo "pkt_id,timestamp,action,label,s_ip,s_port,d_ip,d_port,payload" > $FILE_PACKET_LOG
	echo "event,s_ip,s_port,d_ip,d_port,action,timestamp" > $FILE_FIREWALL_LOG
	echo "pkt_id,s_ip,s_port,d_ip,d_port,label,timestamp,strategy" > $FILE_IDS_LOG
	echo "event,timestamp" > $FILE_ADMIN_LOG
	echo "event,timestamp,reporter" > $FILE_EVENT_IMPORTANT
	echo `date '+%s'` > $FILE_START_TIME
fi

