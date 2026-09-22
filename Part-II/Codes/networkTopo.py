from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.term import makeTerm

import argparse

# The following is the address (fixed IP and MAC)

IP_CLIENT = "10.0.1.5/24"
IP_SERVER1 = "10.0.1.2/24"
IP_SERVER2 = "10.0.1.3/24"

MAC_CLIENT = "00:00:00:00:00:03"
MAC_SERVER1 = "00:00:00:00:00:01"
MAC_SERVER2 = "00:00:00:00:00:02"

IP_BASE = "10.0.1.0/24"

# Single-switch topology with one client and two servers
class CourseworkTopo(Topo):

    def build(self) -> None:
        # Add a single Open vSwitch
        s1 = self.addSwitch("s1")

        # Add hosts with fixed IP/MAC addresses (as required)
        h_client = self.addHost(
            "client", ip=IP_CLIENT, mac=MAC_CLIENT
        )
        h_s1 = self.addHost(
            "server1", ip=IP_SERVER1, mac=MAC_SERVER1
        )
        h_s2 = self.addHost(
            "server2", ip=IP_SERVER2, mac=MAC_SERVER2
        )

        # All hosts are directly connected to s1
        self.addLink(h_client, s1)
        self.addLink(h_s1, s1)
        self.addLink(h_s2, s1)


# Create a Mininet network based on the topology, connect to the remote controller, and then start the CLI for testing
def build_and_run(controller_ip: str, controller_port: int, open_terms: bool) -> None:

    topo = CourseworkTopo()

    net = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=None,          # controller is added explicitly below
        autoSetMacs=False,
        autoStaticArp=False,
        ipBase=IP_BASE,
    )

    # Add a remote controller c0 with given IP and port
    info("*** Adding remote controller at %s:%d\n" % (controller_ip, controller_port))
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    # Start the network (controller, switch, and hosts)
    info("*** Starting network\n")
    net.start()

    # Optionally open xterm windows to simplify experiments
    if open_terms:
        info("*** Opening xterms for controller, switch, and hosts\n")
        net.terms += makeTerm(c0)
        net.terms += makeTerm(net.get("s1"))
        net.terms += makeTerm(net.get("client"))
        net.terms += makeTerm(net.get("server1"))
        net.terms += makeTerm(net.get("server2"))

    info("*** Network is ready. Use the CLI for testing.\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()

# Parse command-line arguments: controller IP/port and xterm option.
def parse_args():
    parser = argparse.ArgumentParser(
        description="CAN201 Part II - SDN redirection topology"
    )
    parser.add_argument(
        "--cip", dest="cip", default="127.0.0.1",
        help="remote controller IP (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--cport", dest="cport", type=int, default=6633,
        help="remote controller port (default: 6633)",
    )
    parser.add_argument(
        "--xterms", action="store_true",
        help="open xterm windows for debugging",
    )
    return parser.parse_args()

# Main entry point: set loglevel, parse args, then build and run the topology.
if __name__ == "__main__":
    setLogLevel("info")
    args = parse_args()
    build_and_run(args.cip, args.cport, args.xterms)
