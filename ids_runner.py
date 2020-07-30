from scapy.all import *
from utils import SOCKFILE, DELIMITER

import socket
import random

iface = "s1-eth5"

def fake_ids(pkt):
    time = pkt.time     # or check pkt[TCP].options
    #data = pkt.load
    data = "FAKE"
    # pkt can be used as dictionary-like stuff already
    # print(time, data, pkt)
    return random.choice(["DOS", "R2L", "U2R"])

def send_alert(alert):
    print("send alert:", alert)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(SOCKFILE)
    sock.send(alert)

def analyze_packet(pkt):
    label = fake_ids(pkt)
    s_ip = pkt[IP].src
    s_port = pkt[TCP].sport
    d_ip = pkt[IP].dst
    d_port = pkt[TCP].dport
    
    data = "NOPAYLOAD"
    if 'Raw' in pkt:
        data = pkt['Raw'].load.split(r"\r\n")
    five_bytes = " ".join(["%02x" % ord(ch) for ch in data][:10])

    # alert message <label, s_ip, s_port, d_ip, d_port, data>
    alert = DELIMITER.join([label, s_ip, str(s_port), d_ip, str(d_port), data])
    send_alert(alert)
    print("pkt [%s:%d --> %s:%d][%s]has been analyzed." % (s_ip, s_port, d_ip, d_port, five_bytes))

if __name__ == '__main__':
    print("Start sniffing...")
    sniff(iface = iface,
          prn = analyze_packet,
          filter = "tcp")

