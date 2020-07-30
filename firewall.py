# SDN firewall as core

# One step toward self-adaptive firewalls, capable of automatically
# setting the filtering rules.
# It (individually) acts like a stateless packet filtering, working with
# statically configured rules. Equipped with a powerful IDS or other traffic
# analyzer, it can be upgraded to a stateful packet filtering with capability
# of inspection and control, pretty close to an IPS.
# In this project, it integrates a smart traffic analyzer, then turns its flow
# to a loop as below:
#   1. As an app of controller, recevie packet P through SBI.
#   2. Send an instruction to switch for each filtering rules.
#       - accept/redirect. Update or make an new flow entry, in which the
#         out port is specified as usual or by configuration. Always add an
#         extra out port to analyzer.
#       - drop. Clear related entry.
#   3. Decide the out port for P according filtering rules, with an extra
#      one enabling switch to mirror itself to analyzer as well.
#   4. Send the constructed output packet to switch through SBI.
# Moreover, it rectifies filtering rules whenever altered by analyzer. It
# receives from analyzer a label L for a certain packet as a deferred response,
# decides an action A(alert/drop/redirect) according L and pre-configuration,
# then modifies filtering rules according A, which will take effect from the
# moment when the next packet-in event arrived.

import sys
import smart_ids
import web_admin
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

import csv  # cope with firewall.rule and ids.rule

firewall_rule_file = "./rules/firewall.rule"
ids_rule_file = "./rules/ids.rule"
log_file = "./log/alert.pkt"

class BasicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'alerter' : AlertObserver}

    def __init__(self, *args, **kwargs):
        super(BasicFirewall, self).__init__(*args, **kwargs)
        self.name = "firewall"
        self.mac_to_port = {}
        # self.snort_port = 3
        self.redirect_port = 4      # TODO: consider being configurable!
        self.ids_port = 5
        self.alerter = kwargs['alerter']
        # self.alerter.start()          # start() has been implicitly called here

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            # TODO: may not support "any" if simply clear by match
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      instructions=inst, command = ofproto.OFPFC_ADD)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        # exclude table-miss entry
        if priority > 0:
            kwargs['idle_timeout'] = 5
        
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

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
        dst = eth.dst
        src = eth.src
        
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # ignoring others except ipv4-tcp packets
        protocols = self.get_protocols(pkt)
        if 'ipv4' not in protocols or 'tcp' not in protocols:
            return

        p_ipv4 = protocols['ipv4']
        p_tcp = protocols['tcp']        

        # start filtering
        matched = False
        blocked = True
        # typical firewall rules as:
        #   id, s_ip, s_port, d_ip, d_port, action
        #   1, 10.0.0.1, 80, 10.0.0.2, any, accept
        #   2, 10.0.0.2, any, 10.0.0.3, 135, redirect
        with open(firewall_rule_file) as frfile:
            rules = csv.DictReader(frfile)
            for r in rules:
                rid = r['id']
                s_ip = r['s_ip']
                s_port = r['s_port']
                d_ip = r['d_ip']
                d_port = r['d_port']
                act = r['action']
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

                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    if act == "redirect":
                        out_port = self.redirect_port

                    # mirror all later-matched packets to ids
                    actions = [parser.OFPActionOutput(out_port),
                               parser.OFPActionOutput(self.ids_port)]
                    if act == "drop":
                        actions = []        # TODO: consider forwarding to ids only
                    self.add_flow(datapath, 1, match1, actions)
                    self.add_flow(datapath, 1, match2, actions)

                # check if current packet matches
                if not matched:
                    if s_ip != "any" and s_ip != p_ipv4.src:
                        continue
                    if s_port != "any" and int(s_port) != p_tcp.src_port:
                        continue
                    # match only once, i.e., match the highest one
                    matched = True
                    if act != "drop":
                        blocked = False
                        actions_saved = [parser.OFPActionOutput(out_port),
                                         parser.OFPActionOutput(self.ids_port)]

        # here all rules have applied as flow entry on switch

        if not blocked:
            # forward current packet, actions have been determined
            actions = actions_saved
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
        action = None
        with open(ids_rule_file) as irf:
            rules = csv.DictReader(irf)
            for r in rules:
                if r['label'] == msg.label:
                    action = r['action']
                    break
        
        # TODO: consider clearing related or all flow entries immediately
        # The sooner the next packet-in arrives, the earlier the new rule
        # takes effect. For the present, idle_timeout holds the interval.

        if action == "alert":
            self._handle_alert(msg)
        elif action == "drop":
            self._handle_drop(msg)
        elif action == "redirect":
            self._handle_redirect(msg)

        PacketLogger.record(action, msg)

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

    def _handle_redirect(self, msg):
        self.logger.info("[redirect][%s] %s:%d --> %s:%d", msg.label,
                         msg.s_ip, msg.s_port, msg.d_ip, msg.d_port)
        
        # insert <id, s_ip, s_port, any, any, redirect>
        kwargs = dict(ruletype = "firewall",
                      s_ip = msg.s_ip, s_port = msg.s_port,
                      d_ip = "any", d_port = "any", action = "redirect")
        RuleWriter.insert_ahead(**kwargs)



        
