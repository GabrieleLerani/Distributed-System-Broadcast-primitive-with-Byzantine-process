# Broadcast primitive with Byzantine processes
## Overview
Byzantine fault-tolerant algorithms, particularly those related to broadcast, are relevant for modern applications due to the increasing complexity and interconnectivity of distributed systems. In the context of Byzantine processes, where some nodes may exhibit arbitrary and malicious behavior, broadcast algorithms play a crucial role in ensuring the reliability and integrity of communication. <br>
In blockchain systems, Byzantine fault tolerance is a key consideration. Broadcast algorithms contribute to the consensus mechanisms that ensure all nodes agree on the state of the distributed ledger, even in the presence of malicious actors.
## Goal
Carry out a dependability evaluation (performance and functionality) of alternative
solutions to the Byzantine Reliable Broadcast problem, comparing a solution
assuming authenticated messages with others considering authenticated links.
Consider the following protocols in the evaluation:
- Authenticated Links - Double Echo (Bracha)
- Authenticated Messages - https://arxiv.org/pdf/2102.07240.pdf (page 7)
- Hash Based https://arxiv.org/abs/2007.14990
- Erasure code base https://arxiv.org/abs/2007.14990
## Result
We implemented all in python and we used mininet for simulations with 20 processes placed using a star topology

Metrics: time (ms), memory peak (MB), Bandwidth (KB/s)
Payload (Bytes):
- 256
- 512
- 1024
- 2048

The plot below shows how AM (Authenticated messages) is very slow due to the usage of digital signature compared to all the other. Even though it guarantees the requirement of non-repudiation. The algorithm that shows the greatest scalability appears to be the HB (hash based) due to fixed size messages.

![BAR-BW-1GB-20-proc](https://github.com/GabrieleLerani/Distributed-System-Broadcast-primitive-with-Byzantine-process/assets/92364167/6f1557b5-ad56-4636-8fb1-6108c91c1d33)


## Usage
First you have to clone or download git repository then do the following commands:
1) Install python and pip if you don't have with:
	```shell
	sudo apt update  
	sudo apt install python3
	sudo apt install python3-pip
	
2) Move in /src,create a virtual environment and activate it:
	```shell
	python -m venv env && source env/bin/activate

3) Install required packages:
	```shell
	pip install -r requirements.txt

4) Install docker on linux, you can find support here https://docs.docker.com/engine/install/

5) Download onos controller image:
	```shell
	sudo docker run -t -d -p 8181:8181 -p 8101:8101 -p 5005:5005 -p 830:830 --name onos onosproject/onos

6) Access to http://172.17.0.2:8181/onos/ui/login.html and login with user: onos and password: rocks

7) Open the menu on the top left and activate Reactive Forwarding and Openflow Provider Suite

8) Move in  /src and start a topology with 4 hosts:
	```shell
	sudo mn --topo linear,4 --link tc,bw=100,delay=0.2ms --mac --controller=remote,ip=172.17.0.2 --switch ovs,protocols=OpenFlow13

9) From mininet CLI start host session with:
	```shell
	xterm h1 h2 h3 h4

10) Execute for each host:
	```shell
	source env/bin/activate

11) Run in h1:
	```shell
	python BRB.py --type N --number 4 -a BRACHA --broadcaster

12) Run in h2, h3, h4:
	```shell
	python BRB.py --type N --algorithm BRACHA
