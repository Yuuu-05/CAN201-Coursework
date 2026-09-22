from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, in_proto
from ryu.lib.packet import tcp

# The specified address and MAC

CLIENT_IP = "10.0.1.5"
SERVER1_IP = "10.0.1.2"
SERVER2_IP = "10.0.1.3"

CLIENT_MAC = "00:00:00:00:00:03"
SERVER1_MAC = "00:00:00:00:00:01"
SERVER2_MAC = "00:00:00:00:00:02"

# Custom redirecting controller application, subclass of RyuApp
class CourseworkRedirect(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CourseworkRedirect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


    # # Utility helpers
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=5, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Build instruction list that applies the given actions
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]

        # Construct FlowMod message depending on whether buffer_id is present
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                idle_timeout=idle_timeout,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                idle_timeout=idle_timeout,
                match=match,
                instructions=inst,
            )
        datapath.send_msg(mod)

    # Send unmatched packets to controller (table-miss entry)
    def _install_table_miss_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Empty match: matches all packets
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]

        # Unmatched packets are sent to the controller
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            idle_timeout=0,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    # Maintain a MAC learning table for each switch
    def _learn_host(self, dpid, mac, port):
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][mac] = port

    # Look up the port for a given MAC address on a given switch
    def _lookup_port(self, dpid, mac):
        return self.mac_to_port.get(dpid, {}).get(mac)

    # Ryu event handlers

    # Triggered when a switch connects: install table-miss flow entry
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info("Switch connected (redirect app): dpid=%s",
                         datapath.id)
        self._install_table_miss_flow(datapath)

    # Main Packet-In handler: learning-switch behaviour plus redirect logic
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        in_port = msg.match["in_port"]

        # Parse the raw Ethernet frame
        pkt = packet.Packet(data=msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Learn the source MAC on this port
        self._learn_host(dpid, src, in_port)

        # Fallback behaviour: normal learning switch
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Decode IPv4 and check for ICMP/TCP to apply special logic
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            if ip_pkt.proto == in_proto.IPPROTO_ICMP:
                # ICMP packets are forwarded by the learning-switch behaviour (no special flows).
                pass
            elif ip_pkt.proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    # Try to install redirect flows for this TCP SYN (if applicable)
                    handled = self._handle_tcp_redirect(
                        datapath, in_port, ip_pkt, tcp_pkt, msg.buffer_id
                    )
                    if handled:
                        # Current buffered SYN has been handled via redirect flows, do not send an extra PacketOut here
                        actions = None

        # Only send PacketOut when actions are still defined
        if actions is not None:
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data,
                )
            else:
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=None,
                )
            datapath.send_msg(out)

    # Redirect logic

    def _handle_tcp_redirect(self, datapath, in_port, ip_pkt, tcp_pkt, buffer_id):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        sport = tcp_pkt.src_port
        dport = tcp_pkt.dst_port

        # Only handle the initial SYN from the client to SERVER1.
        is_syn = (tcp_pkt.bits & tcp.TCP_SYN) != 0
        is_ack = (tcp_pkt.bits & tcp.TCP_ACK) != 0
        if not (is_syn and not is_ack and
                src_ip == CLIENT_IP and dst_ip == SERVER1_IP):
            return False

        # We need the ports towards the client and server2.
        client_port = in_port
        server2_port = self._lookup_port(dpid, SERVER2_MAC)
        if server2_port is None:
            # If we have not yet learned server2's port, we can only flood for now.
            self.logger.debug("Redirect: unknown port for server2, flooding")
            return False

        self.logger.info(
            "Installing redirect flows for TCP %s:%d -> %s:%d to %s (dpid=%s)",
            src_ip, sport, dst_ip, dport, SERVER2_IP, dpid,
        )

        # Forward direction:
        # Client -> logical Server1, but we rewrite and forward to Server2.
        fwd_match = parser.OFPMatch(
            in_port=client_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=in_proto.IPPROTO_TCP,
            ipv4_src=CLIENT_IP,
            ipv4_dst=SERVER1_IP,
            tcp_src=sport,
            tcp_dst=dport,
        )
        fwd_actions = [
            parser.OFPActionSetField(eth_dst=SERVER2_MAC),
            parser.OFPActionSetField(ipv4_dst=SERVER2_IP),
            parser.OFPActionOutput(server2_port),
        ]

        # Reverse direction:
        # Server2 -> Client, but we rewrite the headers so it looks like Server1 -> Client.
        rev_match = parser.OFPMatch(
            in_port=server2_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=in_proto.IPPROTO_TCP,
            ipv4_src=SERVER2_IP,
            ipv4_dst=CLIENT_IP,
            tcp_src=dport,
            tcp_dst=sport,
        )
        rev_actions = [
            parser.OFPActionSetField(eth_src=SERVER1_MAC),
            parser.OFPActionSetField(ipv4_src=SERVER1_IP),
            parser.OFPActionOutput(client_port),
        ]

        # Use buffer_id on the forward direction so the buffered SYN
        # goes through the newly installed redirect flow.
        self._add_flow(
            datapath, priority=50, match=fwd_match,
            actions=fwd_actions, idle_timeout=5,
            buffer_id=buffer_id,
        )

        # Install the reverse-direction redirect flow normally.
        self._add_flow(
            datapath, priority=50, match=rev_match,
            actions=rev_actions, idle_timeout=5,
        )

        return True
