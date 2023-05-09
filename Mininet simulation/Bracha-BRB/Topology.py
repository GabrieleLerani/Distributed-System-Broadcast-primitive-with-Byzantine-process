#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import CPULimitedHost, Host, Node
from mininet.topo import Topo
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from mininet.util import ipAdd
from subprocess import call, Popen, PIPE
from threading import Thread
import threading
import time


CHANNEL_BANDWIDTH = 10  # Mbps
DELAY = 0.06  # ms

setLogLevel("warning")


# Create a single switch topology
def create_single_network(N):
    net = Mininet(
        topo=None,
        host=Host,
        # host=CPULimitedHost,
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

    info("*** Create one switch\n")
    switch = net.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")

    # info("*** Add NAT\n")
    # net.addNAT().configDefault()

    # Start from 2 because the first host is the NAT
    info("*** Add hosts\n")
    # hosts = [net.addHost("h%i" % i, ip="10.0.0.%i" % i) for i in range(2, N + 2)]
    hosts = [net.addHost("h%i" % i, ip="10.0.0.%i" % i) for i in range(1, N + 1)]

    info("*** Wire up hostes\n")
    for host in hosts:
        # limit cpu utilization of each host
        net.addLink(host, switch, bw=CHANNEL_BANDWIDTH, delay=DELAY)

    info("*** Starting network\n")
    net.build()
    info("*** Starting controller\n")
    for controller in net.controllers:
        controller.start()

    info("*** Starting switch\n")
    net.get("s1").start([c0])

    info("*** Post configure switches and hosts\n")
    # Test ping reachability
    net.pingAll()
    net.start()
    return net


# create a linear topology with N switches and N hosts
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
            net.addLink(last, switch, bw=CHANNEL_BANDWIDTH, delay=DELAY)
        last = switch

    info("*** Wire up hostes\n")
    for host, switch in zip(hosts, switches):
        net.addLink(host, switch, bw=CHANNEL_BANDWIDTH, delay=DELAY)

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
    net.start()
    net.pingAll()

    return net


# The following method attaches N new host to an existing network
# TODO it's valid only for single switch topology, modify to adapt to other topology
def add_processes(net, N):
    num_hosts = len(net.hosts)
    switch = net.get("s1")
    for i in range(N):
        host_index = num_hosts + i + 1
        host_name = f"h{host_index}"
        new_host_ip = f"10.0.0.{host_index}"
        new_host = net.addHost(name=host_name, ip=new_host_ip)
        new_host.cmd("ifconfig lo up")
        net.addLink(new_host, switch, bw=CHANNEL_BANDWIDTH, delay=DELAY)
        new_host.setIP(
            ip="10.0.0.{}".format(host_index),
            intf="h{}-eth0".format(host_index),
        )

    net.start()
    net.pingAll()
    return net


# To run hosts I need mininet instance, message, round and simulation number
# are used to initialize debug folder for each process during the simulation
def run_hosts(net, size, round, sim_number, message):
    # server_node = net.get("nat0")
    # t = Thread(target=run_server, args=(server_node,))
    # t.start()

    # Wait for the server initialization
    # time.sleep(0.2)

    # for i in range(2, len(hosts) + 2):

    hosts = net.hosts
    
    info("*** Executing BRB\n")
    for i in range(1 ,len(hosts) + 1):
        
        if i == 1:
            sender = net.get("h%i" % i)

            t = Thread(
                target=run_sender,
                args=(
                    sender,
                    message,
                    size,
                    round,
                    sim_number,
                ),
            )
            t.start()
            
            # Used to allow sender to start
            # time.sleep(0.1)
        else:
            receiver = net.get("h%i" % i)

            t = Thread(
                target=run_receiver,
                args=(
                    receiver,
                    size,
                    round,
                    sim_number,
                ),
            )
            t.start()
            

def run_sender(sender, message, payload_size, round, sim_number):
    
    print(f"--- Executing sender round:{round}, exec:{sim_number}")
    sender.pexec(
        [
            "python3",
            "ProcessMain.py",
            message,
            "%i" % payload_size,
            "%i" % round,
            "%i" % sim_number,
        ]
    )


def run_receiver(receiver, payload_size, round, sim_number):
    
    print(f"--- Executing receiver round:{round}, exec:{sim_number}")
    receiver.pexec(
        [
            "python3",
            "ProcessMain.py",
            "%i" % payload_size,
            "%i" % round,
            "%i" % sim_number,
        ]
    )


def run_server(server):
    server.pexec(["python3", "ServerMain.py"])
    info("*** Server started\n")


def free_space(net):
    net.stop()
