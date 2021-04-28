from smart_ids import IDS_Engine

from scapy.all import *
from utils import SOCKFILE_IDS_ALERT, DELIMITER
from utils import PacketLogger, getActionForLabel

import socket
import random

iface = "s1-eth5"


def fake_ids(pkt):
    time = pkt.time     # or check pkt[TCP].options
    #data = pkt.load
    data = "FAKE"
    # pkt can be used as dictionary-like stuff already
    # print(time, data, pkt)
    return random.choice(['Normal', 'DoS', 'Generic'])

def send_alert(alert):
    print("send alert:", alert)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(SOCKFILE_IDS_ALERT)
    sock.send(alert.encode())

def analyze_packet(pkt):
    s_ip = pkt[IP].src
    s_port = pkt[TCP].sport
    d_ip = pkt[IP].dst
    d_port = pkt[TCP].dport
    
    data = "NOPAYLOAD"
    ten_bytes = ""
    if 'Raw' in pkt:
        data = pkt['Raw'].load
    try:
        ten_bytes = " ".join(["%02x" % ord(ch) for ch in data][:10])
    except:
        pass

    label = IDS_Engine.IDS(pkt, pkt.time)   # call IDS
    # label = fake_ids(pkt)
    
    action = getActionForLabel(label)
    PacketLogger.record(action, label, s_ip, s_port, d_ip, d_port, str(data))
    
    if label != "Normal":
        # alert message <label, s_ip, s_port, d_ip, d_port, data>
        alert = DELIMITER.join([label, s_ip, str(s_port), d_ip, str(d_port), str(data)])
        send_alert(alert)
    print("pkt [%s:%d --> %s:%d][%s] has been analyzed." % (s_ip, s_port, d_ip, d_port, ten_bytes))

if __name__ == '__main__':
    print("Start sniffing...")
    random.seed(0)
    sniff(iface = iface,
          prn = analyze_packet,
          filter = "tcp")

