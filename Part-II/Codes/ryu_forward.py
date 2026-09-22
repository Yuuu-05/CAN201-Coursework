from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, in_proto
from ryu.lib.packet import tcp


# Custom forwarding controller application, subclass of RyuApp
class CourseworkForwarding(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CourseworkForwarding, self).__init__(*args, **kwargs)
        # For each switch (dpid), store a dict: MAC -> port
        self.mac_to_port = {}


    # Utility helpers
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=5, buffer_id=None):

        # Get OpenFlow protocol-related objects
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
        # Unmatched packets are sent to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        # idle_timeout = 0 -> never expires (allowed for table-miss)
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

    # Ryu event handlers

    # Triggered when a switch connects: install table-miss flow entry
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        self.logger.info("Switch connected: dpid=%s", datapath.id)
        self._install_table_miss_flow(datapath)

    # Handle all Packet-In messages from switches
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

        # Ignore LLDP to avoid confusing topology discovery
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Learn the source MAC on this port
        self._learn_host(dpid, src, in_port)

        # Default: flood if destination is unknown
        out_port = ofproto.OFPP_FLOOD
        if dpid in self.mac_to_port and dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]

        # Try to decode upper-layer protocols
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            # ICMP: install short-lived **bidirectional** flow entries
            if ip_pkt.proto == in_proto.IPPROTO_ICMP:
                self._handle_icmp(datapath, in_port, out_port,
                                  ip_pkt, msg.buffer_id)

            # TCP: only install flows on the **first SYN**
            elif ip_pkt.proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    self._handle_tcp(
                        datapath, in_port, out_port,
                        ip_pkt, tcp_pkt, msg.buffer_id
                    )

        # Always forward the current packet (controller acts as fallback)
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

    # Protocol-specific handlers

    # Install bidirectional short-lived flows for ICMP echo traffic.
    def _handle_icmp(self, datapath, in_port, out_port, ip_pkt, buffer_id):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # If the destination is still unknown (flood), do not install a flow yet.
        if out_port == ofproto.OFPP_FLOOD:
            return

        # Forward direction: src -> dst
        fwd_match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=in_proto.IPPROTO_ICMP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
        )
        fwd_actions = [parser.OFPActionOutput(out_port)]

        # Reverse direction: dst -> src
        rev_match = parser.OFPMatch(
            in_port=out_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=in_proto.IPPROTO_ICMP,
            ipv4_src=ip_pkt.dst,
            ipv4_dst=ip_pkt.src,
        )
        rev_actions = [parser.OFPActionOutput(in_port)]

        self.logger.debug(
            "Installing ICMP flows %s <-> %s (dpid=%s)",
            ip_pkt.src, ip_pkt.dst, datapath.id
        )

        # Use buffer_id on the forward rule so this SYN is forwarded via the new flow.
        self._add_flow(
            datapath, priority=10, match=fwd_match,
            actions=fwd_actions, idle_timeout=5,
            buffer_id=buffer_id,
        )
        # Reverse direction is installed without buffer_id (no packet buffered).
        self._add_flow(
            datapath, priority=10, match=rev_match,
            actions=rev_actions, idle_timeout=5,
        )

    # Install **bidirectional** flows for a TCP connection, but only when seeing the very first SYN (SYN=1, ACK=0)
    def _handle_tcp(self, datapath, in_port, out_port,
                    ip_pkt, tcp_pkt, buffer_id):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Only install flows on the initial SYN (SYN=1, ACK=0).
        is_syn = (tcp_pkt.bits & tcp.TCP_SYN) != 0
        is_ack = (tcp_pkt.bits & tcp.TCP_ACK) != 0
        if not (is_syn and not is_ack):
            # All non-SYN TCP packets rely on existing flows.
            return

        # If the output port is still FLOOD, do not install flows yet.
        if out_port == ofproto.OFPP_FLOOD:
            return

        self.logger.info(
            "Initial TCP SYN %s:%d -> %s:%d (dpid=%s)",
            ip_pkt.src, tcp_pkt.src_port, ip_pkt.dst, tcp_pkt.dst_port,
            datapath.id,
        )

        # Forward direction: client -> server
        fwd_match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=in_proto.IPPROTO_TCP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            tcp_src=tcp_pkt.src_port,
            tcp_dst=tcp_pkt.dst_port,
        )
        fwd_actions = [parser.OFPActionOutput(out_port)]

        # Reverse direction: server -> client
        rev_match = parser.OFPMatch(
            in_port=out_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=in_proto.IPPROTO_TCP,
            ipv4_src=ip_pkt.dst,
            ipv4_dst=ip_pkt.src,
            tcp_src=tcp_pkt.dst_port,
            tcp_dst=tcp_pkt.src_port,
        )
        rev_actions = [parser.OFPActionOutput(in_port)]

        # Use buffer_id on the forward direction so the buffered SYN is
        self._add_flow(
            datapath, priority=20, match=fwd_match,
            actions=fwd_actions, idle_timeout=5,
            buffer_id=buffer_id,
        )
        # Install the reverse-direction flow normally
        self._add_flow(
            datapath, priority=20, match=rev_match,
            actions=rev_actions, idle_timeout=5,
        )
