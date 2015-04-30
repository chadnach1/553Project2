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
SOCKET_SOURCE = 4050
PUSHBACK_SOCKET = 4040
REMOTE = True


class StatMonitor(object):
    """ Datastructure for detecting DoS attacks and identifying attackers
    """
    def __init__(self, tdelta=1.0, delta=1000, maxlen=5, server=HOST_SERVER, count=10):
        self.records = defaultdict(list)
        self.portnames = {}
        self.tdelta = tdelta                # time delta between polls
        self.delta = delta                  # max bandwidth
        self.maxlen = maxlen                # window size
        self.server = server                # protected server
        self.count = count                  # ticks before removing QoS and adding drop flow
        self.lock = threading.Lock()        # lock
        self.attackers = []                 # list of (attacker, count)
        self.attackerset = set()            # set of local attackers blocked
        self.remote_attackers = []          # set of remote attackers
        self.mac_map = defaultdict(set)     # map from (dpid, in_port, out_port) to eth_dst
        self.inv_mac_map = defaultdict(set) # inverse mapping of the above

    def update_flow(self, dpid, in_port, out_port, eth_dst, packets, bytez):
        with self.lock:
            history = self.records[dpid,in_port,out_port,eth_dst]
            history.append(bytez)
            # this is too slow, but leaving it here to show how to mutate lists
            #if len(history) > self.maxlen: history[:] = history[-self.maxlen:]
            if len(history) > self.maxlen: del history[0]
            
            self.mac_map[dpid,in_port,out_port].add(eth_dst)
            self.inv_mac_map[eth_dst].add((dpid,in_port,out_port))
            # our bandwidth algorithm
            delta = sum(map(lambda (x,y): float(x-y)/self.tdelta, 
                            zip(history[1:],history[:-1])))
            dos_bool = delta/float(self.maxlen) > self.delta
            if dos_bool and eth_dst != self.server:
                attacker = int(eth_dst[-5:-3])
                if (attacker > 4 and not REMOTE) or (attacker < 5 and REMOTE):
                    print "REMOTE ATTACK DETECTED"
                    # not using datapath.send_msg here because I'm in the stat_monitor
                    command = "sudo ovs-ofctl -O openflow13 add-flow A in_port=3,eth_dst=" + HOST_SERVER + ",eth_src=" + eth_dst + ",actions=drop"
                    subprocess.call(command, shell=True)
                    self.remote_attackers.append(eth_dst)
                    hub.sleep(1)
                else:
                    pass
        return dos_bool and eth_dst != self.server and int(eth_dst[-5:-3]) < 5

    # I used FlowStats for everything, I hope that's ok.
    # Flows are added immediately after ARPs, so for the purpose of
    # DoS detection, they should be the same, given our assumptions.
    def update_port(self, dpid, port, rx_bytes, tx_bytes):
        with self.lock:
            pass

    def found_attacker(self, mac):
        """ Once the other pushback server finds an attacker
            and sends it here, we add it
        """
        with self.lock:
            if mac not in self.attackerset:
                self.attackers.append((mac,0))
                self.attackerset.add(mac)
                dpid,inp,outp = sorted(self.inv_mac_map[mac], key=lambda x: x[0], reverse=True)[0]
                port = self.portnames[dpid,inp] # egress qos shaping
                command = "sudo ovs-vsctl -- set port " + port + " qos=@newqos \
-- --id=@newqos create qos type=linux-htb \
other-config:max-rate=1000000000 \
queues:1=@q1 \
-- --id=@q1 create Queue other-config:max-rate=50000"
                subprocess.call(command, shell=True)

                dpid,inp,outp = sorted(self.inv_mac_map[mac], key=lambda x: x[0], reverse=True)[0]
                port = self.portnames[dpid,inp] # egress qos shaping
                command = "sudo ovs-ofctl -O openflow13 add-flow " + port[:2] + " in_port=" + str(outp) + ",eth_src=" + mac + ",eth_dst=" + HOST_SERVER + ",actions=set_queue:1"
                subprocess.call(command, shell=True)

    def increment_times(self):
        with self.lock:
            attackers = map(lambda (mac,count): (mac,count+1), self.attackers)
            for (mac,_) in filter(lambda (_, count): count >= self.count, attackers):
                # remove qos policing and install drop flow
                dpid,inp,outp = sorted(self.inv_mac_map[mac], key=lambda x: x[0], reverse=True)[0]
                port = self.portnames[dpid,inp]
                command = "sudo ovs-ofctl -O openflow13 del-flows " + port[:2] + " eth_dst=" + HOST_SERVER + ",in_port=" + str(outp)
                subprocess.call(command, shell=True)
                command = "sudo ovs-ofctl -O openflow13 add-flow " + port[:2] + " in_port=" + str(outp) + ",eth_dst=" + HOST_SERVER + ",eth_src=" + mac + ",actions=drop"
                subprocess.call(command, shell=True)
                
            self.attackers = filter(lambda (_, count): count < self.count, attackers)

class DosDetectorSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DosDetectorSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tdelta = 1 #seconds
        self.delta = 5000 #bytes
        self.maxlen = 5 #history window
        self.count = 10
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("localhost", SOCKET_SOURCE))
        self.stat_monitor = StatMonitor(self.tdelta, self.delta, self.maxlen, HOST_SERVER, self.count)
        self.pushback_thread = hub.spawn(self._pushback_monitor)
        self.increment_thread = hub.spawn(self._stat_monitor)

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

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

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

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        for p in body:
            self.stat_monitor.portnames[datapath.id, p.port_no] = p.name

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
            if self.stat_monitor.update_flow(
                    dpid, in_port, out_port, eth_dst, packets, bytez) and not REMOTE:
                print "LOCAL ATTACK DETECTED"
                print "Attacker: " + eth_dst
                match = datapath.ofproto_parser.OFPMatch(eth_src=eth_dst,
                                                         in_port=out_port)
                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match,
                    command=datapath.ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
                    priority=0x8000, flags=datapath.ofproto.OFPFF_SEND_FLOW_REM)
                datapath.send_msg(mod)
            elif eth_dst in map(lambda (mac,_): mac, self.stat_monitor.attackers):
                pass
            
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
        """ Establishes a TCP connection then continuously communicates status 
            with partner server
        """ 
        if not REMOTE:
            self.sock.listen(1)
            connection,_ = self.sock.accept()
        else:
            self.sock.connect(("localhost", PUSHBACK_SOCKET))
        while True:
            if not REMOTE:
                for attacker in self.stat_monitor.remote_attackers:
                    print "sending " + attacker
                    connection.send(attacker)
                    self.stat_monitor.remote_attackers = []
            else:
                mac = self.sock.recv(256)
                print "attacker: " + mac
                self.stat_monitor.found_attacker(mac)
            hub.sleep(self.tdelta)

    def _stat_monitor(self):
        """ Cleans up remote attacker buffer
        """
        while True:
            self.stat_monitor.increment_times()
            hub.sleep(self.tdelta)
