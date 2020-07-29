from ryu.base import app_manager
from ryu.controller import event
from ryu.lib import hub

import os
import struct
import csv

firewall_rule_file = "./rules/firewall.rule"
ids_rule_file = "./rules/ids.rule"
log_file = "./log/alert.pkt"

DELIMITER = '|'
BUFSIZE = 65535
SOCKFILE = "/tmp/ids.alert"

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
		label, s_ip, s_port, d_ip, d_port, data = buf.split(DELIMITER)
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
		self.logger.info("Unix socket start listening...")
		while True:
			data = self.sock.recv(BUFSIZE)
			msg = AlertMessage.parser(data)
			if msg:
                                print("msg:", msg.label, msg.s_ip, msg.s_port, msg.d_ip, msg.d_port, msg.data)
				self.send_event("firewall", EventAlert(msg))

	def start(self):
		if os.path.exists(SOCKFILE):
			os.unlink(SOCKFILE)

		self.sock = hub.socket.socket(hub.socket.AF_UNIX, hub.socket.SOCK_DGRAM)
		self.sock.bind(SOCKFILE)
		hub.spawn(self._observer_loop)

class RuleWriter(object):
	@classmethod
	def insert_ahead(cls, ruletype, s_ip, s_port, d_ip, d_port, action, rid = None):
		if(ruletype == "firewall"):
			file = firewall_rule_file
			file_header = ["id", "s_ip", "s_port", "d_ip", "d_port", "action"]
		else:
			# nobody will touch ids.rule except from web admin
			return

		with open(file, "r+") as f:
			rules = csv.DictReader(f)
                        rids = [int(r['id']) for r in rules]
			# start to write
                        writer = csv.DictWriter(f, file_header)
			f.seek(0)
			writer.writeheader()
			new_rule = dict(id = max(rids) + 1 if not rid else rid,
							s_ip = s_ip,
							s_port = s_port,
							d_ip = d_ip,
							d_port = d_port,
							action = action)
                        writer.writerow(new_rule)
                        for r in rules:
                                if(r['d_ip'] != "d_ip"):
                                        writer.writerow(r)

class PacketLogger(object):
	@classmethod
	def record(cls, action, msg):
		file = log_file
		file_header = ["action", "label",
					   "s_ip", "s_port", "d_ip", "d_port", "hexdata"]
		
		with open(file, "a") as f:
			writer = csv.DictWriter(f, file_header)
			hexdata = " ".join(["%02x" % ord(ch) for ch in msg.data])
			new_record = dict(action = action,
							  label = msg.label,
							  s_ip = msg.s_ip,
							  s_port = msg.s_port,
							  d_ip = msg.d_ip,
							  d_port = msg.d_port,
							  hexdata = msg.data)
                        writer.writerow(new_record)
