#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call, Popen, PIPE
from threading import Thread
import time


SIMULATION_FREQUENCY = 20
CHANNEL_BANDWIDTH = 100  # Mbps
DELAY = 0.2  # ms

setLogLevel("info")


def create_linear_network(N):
    net = Mininet(
        topo=None,
        host=Host,
        build=False,
        ipBase="10.0.0.0/8",
        link=TCLink,
        xterms=False,
        switch=OVSKernelSwitch,
    )

    info("*** Adding controller\n")
    c0 = net.addController(
        name="c0",
        controller=RemoteController,
        ip="172.17.0.2",
        port=6633,
    )

    info("*** Add switches\n")
    switches = [
        net.addSwitch("s%i" % i, cls=OVSKernelSwitch, protocols="OpenFlow13")
        for i in range(1, N + 1)
    ]

    # info("*** Add NAT\n")
    # net.addNAT().configDefault()

    # Start from 2 because the first host is the NAT
    info("*** Add hosts\n")
    # hosts = [net.addHost("h%i" % i, ip="10.0.0.%i" % i) for i in range(2, N + 2)]
    hosts = [net.addHost("h%i" % i, ip="10.0.0.%i" % i) for i in range(1, N + 1)]

    info("*** Wire up switches\n")
    last = None
    for switch in switches:
        if last:
            net.addLink(last, switch, bw=CHANNEL_BANDWIDTH, deley=DELAY)
        last = switch

    info("*** Wire up hostes\n")
    for host, switch in zip(hosts, switches):
        net.addLink(host, switch, bw=CHANNEL_BANDWIDTH, deley=DELAY)

    info("*** Starting network\n")
    net.build()
    info("*** Starting controllers\n")
    for controller in net.controllers:
        controller.start()

    info("*** Starting switches\n")
    for i in range(1, len(switches) + 1):
        net.get("s%i" % i).start([c0])

    info("*** Post configure switches and hosts\n")
    # Test ping reachability
    net.pingAll()
    net.start()
    return net, hosts


def run_hosts(net, hosts, sim_number):
    # server_node = net.get("nat0")
    # t = Thread(target=run_server, args=(server_node,))
    # t.start()

    # Wait for the server initialization
    # time.sleep(0.2)

    # for i in range(2, len(hosts) + 2):

    info("*** Executing BRB\n")
    for i in range(len(hosts), 0, -1):
        time.sleep(0.1)

        # Sender is the process with the highest id
        if i == len(hosts):
            sender = net.get("h%i" % i)

            t = Thread(
                target=run_sender,
                args=(
                    sender,
                    sim_number,
                ),
            )
            t.start()

        else:
            receiver = net.get("h%i" % i)

            t = Thread(
                target=run_receiver,
                args=(
                    receiver,
                    sim_number,
                ),
            )
            t.start()

    # CLI(net)
    # net.stop()


def run_sender(sender, sim_number):
    sender.pexec(["python3", "ProcessMain.py", "Hello", "%i" % sim_number])


def run_receiver(receiver, sim_number):
    receiver.pexec(["python3", "ProcessMain.py", "%i" % sim_number])


def run_server(server):
    server.pexec(["python3", "ServerMain.py"])
    info("*** Server started\n")


def free_space(net):
    # net.cleanup()
    net.stop()
