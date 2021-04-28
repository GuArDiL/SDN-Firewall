# A self-adaptive SDN firewall, automatically setting the filtering rules
# as a response to threats detected.
# 
# It (individually) acts like a stateless packet filtering, working with
# statically configured rules. Equipped with a powerful IDS or other external
# traffic analyzers, it can be stateful, more like an IPS.
#
# In this project, it integrates a smart traffic analyzer. Its workflow are three
# loops as below:
#
# Packet Forwarding Loop: Instruct the switch to mirror all packets.
#   1. Packet In.
#   2. Find for P the highest matched filtering rule R.
#   3. Do nothing if no rule matches.
#   4. Decide the output port for P based on R's action.
#       - accept. Output as usual. That is, output to the port learned before or FLOOD
#         if the destination has not been learned.
#       - redirect. Output to the pre-configured redirect port.
#       - drop. Do nothing.
#   5. Add the pre-configured IDS port to the output port list if not FLOOD.
#   6. Packet Out.
#
# Alerting Loop: Update filtering rules whenever altered by the analyzer.
#   1. Receive from the analyzer a label L for a certain packet as a deferred response.
#   2. Decide an action A based on L and IDS rules (a lable-action table).
#   3. Modify filtering rules based on A. That is, insert the new rule ahead of
#      existing rules and remove all conflicting old rules.
#   4. APPLY ALL filtering rules to all switches. That is, clear all flow entries, add
#      the table-miss entry back, and install a flow entry for each filtering rule.
#       - accept/redirect. Output as in Packet Forwarding Loop.
#       - drop. Drop explicitly (i.e. add a flow entry with CLEAR_ACTION).
#
# Admin Loop: APPLY ALL filtering rules once rules are committed from web admin.
#   - The correctness is ensured by the user who submitted the modification.
#   - The APPLY ALL operation is exactly the same as in Alerting Loop.

from utils import *

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp, udp, arp, icmp
from ryu.app.ofctl.api import get_datapath

import csv  # cope with firewall.rule and ids.rule

firewall_rule_file = "./rules/firewall.rule"
ids_rule_file = "./rules/ids.rule"
log_file = "./log/alert.pkt"

class BasicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'alerter' : AlertObserver, 'reminder' : RuleReminder}

    def __init__(self, *args, **kwargs):
        super(BasicFirewall, self).__init__(*args, **kwargs)
        self.name = "firewall"
        self.ip_to_port = {}
        # self.snort_port = 3
        self.redirect_port = 4      # TODO: consider being configurable!
        self.ids_port = 5
        self.alerter = kwargs['alerter']
        # self.alerter.start()          # start() has been implicitly called here
        self.reminder = kwargs['reminder']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry in reset_flow_table()
        # which would be called by apply_rules_for_all()
        self.apply_rules_for_all()

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            # flow entry for drop action
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      instructions=inst, command=ofproto.OFPFC_ADD)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        # exclude table-miss entry
        # if priority > 0:
        #     kwargs['idle_timeout'] = 5
        
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    def reset_flow_table(self, datapath):
        # remove all flow entries and install table-miss entry back
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # remove all flow entries
        # uncommented parameters are indispensable to clear
        kwargs = dict(datapath=datapath,
                      command=ofproto.OFPFC_DELETE,
                      # priority=1,
                      # buffer_id=ofproto.OFP_NO_BUFFER,
                      out_port=ofproto.OFPP_ANY,
                      out_group=ofproto.OFPG_ANY,
                      # flags=ofproto.OFPFF_SEND_FLOW_REM,
                      # match=parser.OFPMatch(),
                      # instructions=[]
                      ) 
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        
        # install table-miss entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        # dst = eth.dst
        # src = eth.src
        
        dpid = format(datapath.id, "d").zfill(16)
        self.ip_to_port.setdefault(dpid, {})            # ip learning is more efficient

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # ignoring others except ipv4-tcp packets
        protocols = self.get_protocols(pkt)
        if 'ipv4' not in protocols or 'tcp' not in protocols:
            return

        p_ipv4 = protocols['ipv4']
        p_tcp = protocols['tcp']        
        
        # learn an ip address (rather than mac) to avoid FLOOD next time
        # or TODO: consider maintaining an ip-mac-port table to support learn mac from non-ip packet
        self.ip_to_port[dpid][p_ipv4.src] = in_port

        # log packet-in event
        FirewallLogger.recordPacketInEvent(p_ipv4.src, p_tcp.src_port, p_ipv4.dst, p_tcp.dst_port)

        # start filtering
        blocked = True
        # typical firewall rules as:
        #   id, s_ip, s_port, d_ip, d_port, action
        #   1, 10.0.0.1, 80, 10.0.0.2, any, accept
        #   2, 10.0.0.2, any, 10.0.0.3, 135, redirect
        with open(firewall_rule_file) as frfile:
            rules = list(csv.DictReader(frfile))
            for r in rules:
                # get actions for forward and backward rule if matched
                # no rule will be applied to switches in packet-in event now
                # thus the priority parameter makes no difference
                actions1, actions2 = self.apply_rule_for(datapath, r, -1, False)
                
                # check if current packet matches
                # match only once, i.e., match the highest one
                # forward rule matched
                if r['s_ip'] == "any" or r['s_ip'] == p_ipv4.src:
                    if r['s_port'] == "any" or r['s_port'] == p_tcp.src_port:
                        if r['action'] != "drop":
                            blocked = False
                            actions = actions1
                        matched = True
                        FirewallLogger.recordRuleEvent("match", r)
                        break
                # backward fule matched
                if r['d_ip'] == "any" or r['d_ip'] == p_ipv4.src:
                    if r['d_port'] == "any" or r['d_port'] == p_tcp.src_port:
                        if r['action'] != "drop":
                            blocked = False
                            actions = actions2
                        matched = True
                        FirewallLogger.recordRuleEvent("match", r)
                        break

        if not blocked:
            # forward current packet, actions have been determined if not blocked
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(EventAlert, MAIN_DISPATCHER)
    def handle_alert(self, ev):
        # message <label, s_ip, s_port, d_ip, d_port, data>
        # typical alert messages in file as:
        #   DOS, 10.0.0.1, 80, 10.0.0.2, 445, some-serialized-bytes
        msg = ev.msg

        # label-action configuration
        # typical lines as:
        #   DOS, drop
        #   R2L, redirect
        action = getActionForLabel(msg.label)
        
        # DONE: consider clearing related or all flow entries immediately

        FirewallLogger.recordAlertEvent(msg)
        
        if action == "alert":
            self._handle_alert(msg)
        elif action == "drop":
            self._handle_drop(msg)
        elif action == "redirect":
            self._handle_redirect(msg)
        
    def _handle_alert(self, msg):
        self.logger.info("[alert][%s] %s:%d --> %s:%d, data = {", msg.label,
                         msg.s_ip, msg.s_port, msg.d_ip, msg.d_port)
        print(" ".join(["%02x" % ord(ch) for ch in msg.data]))
        self.logger.info("}")

    def _handle_drop(self, msg):
        self.logger.info("[drop][%s] %s:%d --> %s:%d", msg.label,
                         msg.s_ip, msg.s_port, msg.d_ip, msg.d_port)

        # insert <id, s_ip, s_port, any, any, drop>
        kwargs = dict(ruletype = "firewall",
                      s_ip = msg.s_ip, s_port = msg.s_port,
                      d_ip = "any", d_port = "any", action = "drop")
        RuleWriter.insert_ahead(**kwargs)
        self.apply_rules_for_all()

    def _handle_redirect(self, msg):
        self.logger.info("[redirect][%s] %s:%d --> %s:%d", msg.label,
                         msg.s_ip, msg.s_port, msg.d_ip, msg.d_port)
        
        # insert <id, s_ip, s_port, any, any, redirect>
        kwargs = dict(ruletype = "firewall",
                      s_ip = msg.s_ip, s_port = msg.s_port,
                      d_ip = "any", d_port = "any", action = "redirect")
        RuleWriter.insert_ahead(**kwargs)
        self.apply_rules_for_all()

    @set_ev_cls(EventRuleModified, MAIN_DISPATCHER)
    def handle_rule_alert(self, ev):
        self.apply_rules_for_all()
        FirewallLogger.recordAdminSubmit() 
    
    def apply_rules_for_all(self):
        datapaths = get_datapath(self)
        for datapath in datapaths:
            self.reset_flow_table(datapath)     # install table-miss entry here
            with open(firewall_rule_file) as frfile:
                rules = list(csv.DictReader(frfile))
                priority = len(rules)
                for r in rules:
                    self.apply_rule_for(datapath, r, priority)
                    priority -= 1
           
    def apply_rule_for(self, datapath, rule, priority, applied=True):
        dpid = format(datapath.id, "d").zfill(16)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        rid = rule['id']
        s_ip = rule['s_ip']
        s_port = rule['s_port']
        d_ip = rule['d_ip']
        d_port = rule['d_port']
        act = rule['action']
        self.logger.info("Fetch rule %s: %s:%s --> %s:%s %s",
                         rid, s_ip, s_port, d_ip, d_port, act)
        
        # add flow entry for all rules (even drop)
        if act:
            # forward rule
            kwargs1 = dict(eth_type=ether_types.ETH_TYPE_IP,
                           ip_proto=in_proto.IPPROTO_TCP)
            # backward rule
            kwargs2 = dict(eth_type=ether_types.ETH_TYPE_IP,
                           ip_proto=in_proto.IPPROTO_TCP)

            # ignore "any"
            if(s_ip != "any"):
                kwargs1["ipv4_src"] = kwargs2["ipv4_dst"] = s_ip

            if(s_port != "any"):
                kwargs1["tcp_src"] = kwargs2["tcp_dst"] = int(s_port)

            if(d_ip != "any"):
                kwargs1["ipv4_dst"] = kwargs2["ipv4_src"] = d_ip

            if(d_port != "any"):
                kwargs1["tcp_dst"] = kwargs2["tcp_src"] = int(d_port)

            match1 = parser.OFPMatch(**kwargs1)
            match2 = parser.OFPMatch(**kwargs2)
             
            # find learned ip respectively
            out_port1 = out_port2 = ofproto.OFPP_FLOOD
            if dpid in self.ip_to_port:
                if d_ip in self.ip_to_port[dpid]:
                    out_port1 = self.ip_to_port[dpid][d_ip]
                if s_ip in self.ip_to_port[dpid]:
                    out_port2 = self.ip_to_port[dpid][s_ip]

            if act == "redirect":
                out_port1 = out_port2 = self.redirect_port

            # mirror all later-matched packets to ids
            actions1 = [parser.OFPActionOutput(out_port1)]
            if out_port1 != ofproto.OFPP_FLOOD:
                actions1.append(parser.OFPActionOutput(self.ids_port))
            actions2 = [parser.OFPActionOutput(out_port2)]
            if out_port2 != ofproto.OFPP_FLOOD:
                actions2.append(parser.OFPActionOutput(self.ids_port))
            if act == "drop":
                actions1 = actions2 = []        # TODO: consider forwarding to ids only
            
            if applied:
                self.add_flow(datapath, priority, match1, actions1)
                self.add_flow(datapath, priority, match2, actions2)

        return actions1, actions2
