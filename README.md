1) Install python and pip if you don't have with:
	sudo apt update  
	sudo apt install python3
	sudo apt install python3-pip
	
2) Move in /src,create a virtual environment and activate it:
	python -m venv env && source env/bin/activate

3) Install required packages:
	pip install -r requirements.txt

4) Install docker on linux, you can find support here https://docs.docker.com/engine/install/

5) Download onos controller image:
	sudo docker run -t -d -p 8181:8181 -p 8101:8101 -p 5005:5005 -p 830:830 --name onos onosproject/onos
6) Access to http://172.17.0.2:8181/onos/ui/login.html and login with user: onos and password: rocks
7) Open the menu on the top left and activate Reactive Forwarding and Openflow Provider Suite
8) Move in  /src and start a topology with 4 hosts:
	sudo mn --topo linear,4 --link tc,bw=100,delay=0.2ms --mac --controller=remote,ip=172.17.0.2 --switch ovs,protocols=OpenFlow13
9) From mininet CLI start host session with:
	xterm h1 h2 h3 h4
10) Execute for each host:
	source env/bin/activate
11) Run in h1:
	python BRB.py --type N --number 4 -a BRACHA --broadcaster
12) Run in h2, h3, h4:
	python BRB.py --type N --algorithm BRACHA
