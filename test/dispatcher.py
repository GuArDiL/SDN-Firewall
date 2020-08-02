from scapy.all import *
import socket
import fcntl
pcap_file = "./pcap/test2-dos.pcap"

def get_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),
                                        0x8915,
                                        struct.pack("256s", iface[:15]))[20:24])

def dispatch():
    pkts = rdpcap(pcap_file)
    n = min(len(pkts), 8)
    for i in range(n):
        pkt = pkts[i]
        
        if pkt[TCP].dport != 80:
            continue
         
        src = "00:00:00:00:00:02"
        dst = "00:00:00:00:00:01"
        s_ip = "10.0.0.2"
        d_ip = "10.0.0.1"
        
        pkt[Ether].src = src
        pkt[Ether].dst = dst
        pkt[IP].src = s_ip
        pkt[IP].dst = d_ip

        # reset to recalculate
        pkt[IP].len = None
        pkt[IP].checksum = None
        pkt[TCP].len = None
        pkt[TCP].checksum = None
        sendp(pkt)


if __name__ == '__main__':
    dispatch()
