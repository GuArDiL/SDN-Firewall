from ryu.base import app_manager
from ryu.controller import event
from ryu.lib import hub

import os
import struct
import csv
import datetime

pwd = os.path.split(os.path.realpath(__file__))[0]

firewall_rule_file = pwd + "/rules/firewall.rule"
ids_rule_file = pwd + "/rules/ids.rule"
firewall_log_file = pwd + "/log/firewall.log"
ids_log_file = pwd + "/log/ids.log"
packet_log_file = pwd + "/log/pkt.all"
event_important_file = pwd + "/log/event.important"

DELIMITER = '|'
BUFSIZE = 65535
SOCKFILE_IDS_ALERT = "/tmp/ids.alert"
SOCKFILE_RULE_ALERT = "/tmp/rule.alert"

class AlertMessage(object):
    # message <label, s_ip, s_port, d_ip, d_port, data>
    def __init__(self, label, s_ip, s_port, d_ip, d_port, data):
        self.label = label
        self.s_ip = s_ip
        self.s_port = int(s_port)
        self.d_ip = d_ip
        self.d_port = int(d_port)
        self.data = data

    @classmethod
    def parser(cls, buf):
        label, s_ip, s_port, d_ip, d_port, data = buf.decode().split(DELIMITER)
        msg = cls(label, s_ip, s_port, d_ip, d_port, data)
        return msg

class EventAlert(event.EventBase):
    def __init__(self, msg):
        super(EventAlert, self).__init__()
        self.msg = msg

class AlertObserver(app_manager.RyuApp):
    def __init__(self):
        super(AlertObserver, self).__init__()
        self.name = "alerter"
        self.sock = None

    def _observer_loop(self):
        self.logger.info("[AlertObserver] Starts listening to unix socket...")
        while True:
            data = self.sock.recv(BUFSIZE)
            msg = AlertMessage.parser(data)
            if msg:
                self.send_event("firewall", EventAlert(msg))

    def start(self):
        if os.path.exists(SOCKFILE_IDS_ALERT):
            os.unlink(SOCKFILE_IDS_ALERT)

        self.sock = hub.socket.socket(hub.socket.AF_UNIX, hub.socket.SOCK_DGRAM)
        self.sock.bind(SOCKFILE_IDS_ALERT)
        hub.spawn(self._observer_loop)

class EventRuleModified(event.EventBase):
    # require no detailed message
    # only notice firewall applying modified rules from web admin
    def __init(self):
        super(EventRuleModified, self).__init__()

class RuleReminder(app_manager.RyuApp):
    def __init__(self):
        super(RuleReminder, self).__init__()
        self.name = "reminder"
        self.sock = None

    def _observer_loop(self):
        self.logger.info("[RuleReminder] Starts listening to unix socket...")
        while True:
            data = self.sock.recv(BUFSIZE)
            if data:
                self.send_event("firewall", EventRuleModified())
    
    def start(self):
        if os.path.exists(SOCKFILE_RULE_ALERT):
            os.unlink(SOCKFILE_RULE_ALERT)
        
        self.sock = hub.socket.socket(hub.socket.AF_UNIX, hub.socket.SOCK_DGRAM)
        self.sock.bind(SOCKFILE_RULE_ALERT)
        hub.spawn(self._observer_loop)

class RuleWriter(object):
    @classmethod
    def insert_ahead(cls, ruletype, s_ip, s_port, d_ip, d_port, action):
        if(ruletype == "firewall"):
            file = firewall_rule_file
            file_header = ["id", "s_ip", "s_port", "d_ip", "d_port", "action", "timestamp", "source"]
        else:
            # nobody will touch ids.rule except from web admin
            return

        with open(file, "r+") as f:
            # attn: DictReader can be iterated only once
            rules = list(csv.DictReader(f))
            
            # decide rule id
            rid = 10000
            for r in rules:
                if(int(r['id']) < 20000 and int(r['id']) > rid):
                    rid = int(r['id'])
            rid = rid + 1 
            # start to write
            f.seek(0)
            writer = csv.DictWriter(f, file_header)
            writer.writeheader()
            new_rule = dict(id = rid,
                            s_ip = s_ip,
                            s_port = str(s_port),
                            d_ip = d_ip,
                            d_port = str(d_port),
                            action = action,
                            timestamp = timestamp(),
                            source = "firewall")
            
            print("Add rule %s: %s:%s --> %s:%s %s" %
                  (rid, s_ip, s_port, d_ip, d_port, action))
            
            writer.writerow(new_rule)
            FirewallLogger.recordRuleEvent("auto new", new_rule)
            for r in rules:
                # distinct write
                distinct = False
                for kw in file_header[1:5]:
                    if r[kw] != new_rule[kw]:
                        distinct = True
                        break
                if distinct:
                    writer.writerow(r)
                else:
                    FirewallLogger.recordRuleEvent("auto remove", r)
            f.truncate()

class FirewallLogger(object):
    @classmethod
    def recordRuleEvent(cls, action, rule):
        time = timestamp()
        if action == "auto remove":
            event = "|".join(["remove rule", str(rule['id']), "auto"])
        elif action == "auto new":
            event = "|".join(["new rule", str(rule['id']), "auto"])
            recordAsImportant("|".join(["new rule", str(rule['id']), rule['action'],
                                        rule['s_ip']+":"+str(rule['s_port']), rule['d_ip']+":"+str(rule['d_port'])]), time, "firewall")
        elif action == "match":
            event = "|".join(["match rule", str(rule['id'])])

        new_record = dict(event = event,
                          s_ip = rule['s_ip'],
                          s_port = rule['s_port'],
                          d_ip = rule['d_ip'],
                          d_port = rule['d_port'],
                          action = rule['action'],
                          timestamp = time)
        cls.record(new_record)

    @classmethod 
    def recordPacketInEvent(cls, s_ip, s_port, d_ip, d_port):
        event = "packet in"
        time = timestamp()
        new_record = dict(event = event,
                          s_ip = s_ip,
                          s_port = s_port,
                          d_ip = d_ip,
                          d_port = d_port,
                          timestamp = time)
        cls.record(new_record)
        recordAsImportant("packet in", time, "firewall")

    @classmethod    
    def recordAlertEvent(cls, msg):
        event = "|".join(["alert", msg.label])
        new_record = dict(event = event,
                          s_ip = msg.s_ip,
                          s_port = msg.s_port,
                          d_ip = msg.d_ip,
                          d_port = msg.d_port,
                          timestamp = timestamp())
        cls.record(new_record)
    
    @classmethod
    def recordAdminSubmit(cls):
        event = "admin submit"
        new_record = dict(event = event, timestamp = timestamp())
        cls.record(new_record)
 
    def record(new_record):
        file = firewall_log_file
        file_header = ["event", "s_ip", "s_port", "d_ip", "d_port", "action", "timestamp"]
        with open(file, "a") as f:
            writer = csv.DictWriter(f, file_header)
            writer.writerow(new_record)


class PacketLogger(object):
    pkt_id_counter = 1111
    @classmethod
    def record(cls, action, label, s_ip, s_port, d_ip, d_port, data):
        file = packet_log_file
        file_header = ["pkt_id", "timestamp", "action", "label", "s_ip", "s_port", "d_ip", "d_port", "payload"]
        
        time = timestamp()
        with open(file, "a") as f:
            writer = csv.DictWriter(f, file_header)
            # hexdata = " ".join(["%02x" % ord(ch) for ch in msg.data.strip()])
            new_record = dict(pkt_id = cls.pkt_id_counter,
                              timestamp = time,
                              action = action,
                              label = label,
                              s_ip = s_ip,
                              s_port = s_port,
                              d_ip = d_ip,
                              d_port = d_port,
                              payload = data.replace("\r\n", "\\r\\n"))
            writer.writerow(new_record)
        
        if label != "Normal":
            file = ids_log_file
            file_header = ["pkt_id", "s_ip", "s_port", "d_ip", "d_port", "label", "timestamp", "strategy"]
            
            with open(file, "a") as f:
                writer = csv.DictWriter(f, file_header)
                new_record = dict(pkt_id = cls.pkt_id_counter,
                                  s_ip = s_ip,
                                  s_port = s_port,
                                  d_ip = d_ip,
                                  d_port = d_port,
                                  label = label,
                                  timestamp = time,
                                  strategy = action)
                writer.writerow(new_record)
             
            recordAsImportant("|".join(["alert", s_ip+":"+str(s_port), label]), time, "ids")

        cls.pkt_id_counter += 1
    
def recordAsImportant(event, timestamp, reporter):
    file = event_important_file
    file_header = ["event", "timestamp", "reporter"]
    with open(file, "a") as f:
        writer = csv.DictWriter(f, file_header)
        new_record = dict(event = event,
                          timestamp = timestamp,
                          reporter = reporter)
        writer.writerow(new_record)

def getActionForLabel(label):
    action = None
    with open(ids_rule_file, "r") as f:
        rules = csv.DictReader(f)
        for r in rules:
            if r['label'] == label:
                return r['action']
    return "NOACTION"


import datetime
def timestamp():
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%m-%d %H:%M:%S")    
