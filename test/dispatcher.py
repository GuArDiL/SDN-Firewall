from scapy.all import *
import socket
import fcntl
pcap_file = "./test1.pcap"

def get_ip(iface):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),
										0x8915,
										struct.pack("256s", iface[:15]))[20:24])

def dispatch():
	pkts = rdpcap(pcap_file)
	for pkt in pkts:
		pkt[IP].src = "10.0.0.2"
                pkt[IP].dst = "10.0.0.1"

		# reset to recalculate
		pkt[IP].len = None
		pkt[IP].checksum = None
		pkt[TCP].len = None
		pkt[TCP].checksum = None
		sendp(pkt)


if __name__ == '__main__':
	dispatch()
