from smart_ids import IDS_Engine

from scapy.all import *
from utils import SOCKFILE, DELIMITER

import socket
import random

iface = "s1-eth5"

'''
def fake_ids(pkt):
    time = pkt.time     # or check pkt[TCP].options
    #data = pkt.load
    data = "FAKE"
    # pkt can be used as dictionary-like stuff already
    # print(time, data, pkt)
    random.seed(0)
    return random.choice(["DOS", "R2L", "U2R"])
'''

def send_alert(alert):
    print("send alert:", alert)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(SOCKFILE)
    sock.send(alert)

def analyze_packet(pkt):
    s_ip = pkt[IP].src
    s_port = pkt[TCP].sport
    d_ip = pkt[IP].dst
    d_port = pkt[TCP].dport
    
    data = "NOPAYLOAD"
    if 'Raw' in pkt:
        data = pkt['Raw'].load
    try:
        ten_bytes = " ".join(["%02x" % ord(ch) for ch in data][:10])
    except:
        ten_byte = ""
    
    label = IDS_Engine.IDS(pkt, pkt.time)   # call IDS

    # alert message <label, s_ip, s_port, d_ip, d_port, data>
    alert = DELIMITER.join([label, s_ip, str(s_port), d_ip, str(d_port), data])
    send_alert(alert)
    print("pkt [%s:%d --> %s:%d][%s] has been analyzed." % (s_ip, s_port, d_ip, d_port, ten_bytes))

if __name__ == '__main__':
    print("Start sniffing...")
    sniff(iface = iface,
          prn = analyze_packet,
          filter = "tcp")

