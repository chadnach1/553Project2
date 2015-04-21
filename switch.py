# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import defaultdict
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import socket
import subprocess
import threading

HOST_SERVER = "00:00:00:00:01:00"
PUSHBACK_SOCKET = 4050

class StatMonitor(object):
    def __init__(self, tdelta=1.0, delta=1000, maxlen=5, server=HOST_SERVER):
        self.records = defaultdict(list)
        self.tdelta = tdelta
        self.delta = delta
        self.maxlen = maxlen
        self.server = server
        self.lock = threading.RLock()
        self.attackers = []

    def update_flow(self, dpid, in_port, out_port, eth_dst, packets, bytez):
        with self.lock:
            history = self.records[dpid,in_port,out_port,eth_dst]
            history.append(bytez)
            # this is too slow, but leaving it here to show how to mutate lists
            #if len(history) > self.maxlen: history[:] = history[-self.maxlen:]
            if len(history) > self.maxlen: del history[0]
            delta = sum(map(lambda (x,y): float(x-y)/self.tdelta, 
                            zip(history[1:],history[:-1])))
            dos_bool = delta/float(self.maxlen) > self.delta
            if dos_bool and eth_dst != self.server:
                print dpid, in_port, eth_dst
                self.attackers.append((dpid,out_port,eth_dst)) #?
        return dos_bool and eth_dst == self.server
        # PortDescStats?
    def update_port(self, dpid, port, rx_bytes, tx_bytes):
        with self.lock:
            pass

class DosDetectorSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DosDetectorSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tdelta = 1 #seconds
        self.delta = 1000 #bytes
        self.maxlen = 5 #history window
        self.stat_monitor = StatMonitor(self.tdelta, self.delta, self.maxlen) #threadsafe
        self.pushback_thread = hub.spawn(self._pushback_monitor)

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

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

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

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.tdelta)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            dpid = datapath.id
            in_port = stat.match["in_port"]
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match["eth_dst"]
            packets = stat.packet_count
            bytez = stat.byte_count
            # why do we need port stats? answer: we don't
            # flow stats don't include ARP packets, but that doesn't make a big difference
            if self.stat_monitor.update_flow(dpid, in_port, out_port, eth_dst, packets, bytez):
                self.victims.append(eth_dst)
                match = datapath.ofproto_parser.OFPMatch(dl_dst=eth_dst,
                                                         in_port=in_port,
                                                         out_port=out_port)
                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match,
                    command=datapath.ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
                    priority=0x8000, flags=datapath.ofproto.OFPFF_SEND_FLOW_REM)
                datapath.send_msg(mod)
            
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
            port = stat.port_no
            rx_bytes = stat.rx_bytes #stat.rx_packets
            tx_bytes = stat.tx_bytes #stat.tx_packets
            self.stat_monitor.update_port(dpid, port, rx_bytes, tx_bytes)
    
    def _pushback_monitor(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect("localhost", PUSHBACK_SOCKET) # hm this won't work, need diff port
        while True:
            hub.sleep(self.tdelta)
