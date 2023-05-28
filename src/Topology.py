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
from mininet.util import ipAdd, dumpNetConnections
from subprocess import call, Popen, PIPE
from threading import Thread
from mininet.term import makeTerm

CHANNEL_BANDWIDTH = 10  # Mbps
DELAY = 0.001  # ms

setLogLevel("warning")


# Create a single switch topology
def create_single_network(N):
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

    info("*** Create one switch\n")
    switch = net.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")

    # Start from 2 because the first host is the NAT
    info("*** Add hosts\n")
    hosts = [net.addHost("h%i" % i, ip="10.0.0.%i" % i) for i in range(1, N + 1)]

    info("*** Wire up hostes\n")
    for host in hosts:
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


def create_kds_node(net, id):
    switch = net.get("s1")
    h_name = f"h{id}"
    h_ip = f"10.0.0.{id}"
    switch_interface = f"s1-eth{id}"

    new_host = net.addHost(name=h_name, ip=h_ip)

    net.addLink(
        new_host,
        switch,
        intfName2=switch_interface,
        bw=CHANNEL_BANDWIDTH,
        delay=DELAY,
    )

    new_host.setIP(ip=h_ip, intf="h{}-eth0".format(id))
    net.start()
    net.pingAll()


# The following method attaches N new host to an existing single switch network
def add_processes(net, N):
    num_hosts = len(net.hosts)
    switch = net.get("s1")

    for i in range(N):
        host_index = num_hosts + i + 1
        host_name = f"h{host_index}"

        switch_interface = f"s1-eth{host_index}"
        new_host_ip = f"10.0.0.{host_index}"
        new_host = net.addHost(name=host_name, ip=new_host_ip)
        new_host.cmd("ifconfig lo up")

        net.addLink(
            new_host,
            switch,
            intfName2=switch_interface,
            bw=CHANNEL_BANDWIDTH,
            delay=DELAY,
        )
        new_host.setIP(
            ip="10.0.0.{}".format(host_index),
            intf="h{}-eth0".format(host_index),
        )

    net.start()
    net.pingAll()

    return net


# To run hosts I need mininet instance, message, round and simulation number
# are used to initialize debug folder for each process during the simulation
def run_hosts(net, algo, size, round, sim_number, kds_id):
    hosts = net.hosts
    hosts_num = len(hosts) + 1
    threads = []  # Store the threads for synchronization

    print("*** Executing BRB\n")

    kds = algo == "AM"

    kds_ip = f"10.0.0.{kds_id}"

    # if authenticated messages start key distribution server
    if kds:
        # create kds with the id and connect to the switch
        create_kds_node(net, kds_id)

        hosts_num = len(hosts)
        kds_node = net.get("h{}".format(kds_id))
        t = Thread(target=run_kds, args=(kds_node,))
        t.start()
        threads.append(t)  # Add thread to the list

    for i in range(1, hosts_num):
        if i == 1:
            sender = net.get("h%i" % i)

            t = Thread(
                target=run_sender,
                args=(sender, algo, size, round, sim_number, kds, kds_ip),
            )
            t.start()
            threads.append(t)  # Add thread to the list

        else:
            receiver = net.get("h%i" % i)

            t = Thread(
                target=run_receiver,
                args=(
                    receiver,
                    algo,
                    size,
                    round,
                    sim_number,
                    kds,
                    kds_ip,
                ),
            )
            t.start()
            threads.append(t)  # Add thread to the list

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # at the end remove kds node
    if kds:
        remove_node(net, kds_id)


def remove_node(net, id):
    kds_id = f"h{id}"
    node = net.get(kds_id)
    switch = net.get("s1")
    switch.delIntf(f"s1-eth{id}")
    switch.detach(f"s1-eth{id}")
    net.delNode(node)


def run_kds(kds_node):
    print("Running KDS...")

    # set up the environment and execute the command using cmd
    kds_node.cmd(f"source .venv/bin/activate && cd AM/ && python3 KDSMain.py")

    print("KDS terminated-------")


def run_sender(sender, algo, payload_size, round, sim_number, kds, kds_ip):
    print(f"--- Executing sender round:{round}, exec:{sim_number}")
    command = ""
    if kds:
        command = f"source .venv/bin/activate && python3 BRB.py -t S -a {algo} --broadcaster -p {payload_size} -r {round} -s {sim_number} --kds {kds_ip}"
    else:
        command = f"source .venv/bin/activate && python3 BRB.py -t S -a {algo} --broadcaster -p {payload_size} -r {round} -s {sim_number}"

    # set up the environment and execute the command using cmd
    sender.cmd(command)

    print("sender terminated-------")


def run_receiver(receiver, algo, payload_size, round, sim_number, kds, kds_ip):
    print(f"--- Executing receiver round:{round}, exec:{sim_number}")

    command = ""
    if kds:
        command = f"source .venv/bin/activate && python3 BRB.py -t S -a {algo} -p {payload_size} -r {round} -s {sim_number} --kds {kds_ip}"
    else:
        command = f"source .venv/bin/activate && python3 BRB.py -t S -a {algo} -p {payload_size} -r {round} -s {sim_number}"

    # set up the environment and execute the command using cmd
    receiver.cmd(command)

    print("receiver terminated-------")


def free_space(net):
    net.stop()
