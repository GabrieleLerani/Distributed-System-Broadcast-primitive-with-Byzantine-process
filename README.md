1)Install python 3.7 on linux

	sudo add-apt-repository ppa:deadsnakes/ppa
	sudo apt-get update

2)Install pip if it doesn't exist yet

	sudo apt install python3-pip

Docker RabbitMQ

1)Start the Docker with RabbitMQ

	docker run -d -p <ip_address>:5672:5672 -p 15672:15672 rabbitmq:3.8.15-rc.2-management
	
import pyeclib.ec_iface as ec_iface

ec = ec_iface.ECDriver(k=2, m=2, ec_type='liberasurecode_rs_vand')
data = b'hello world'
encoded_data = ec.encode(data)
decoded_data = ec.decode(encoded_data)
assert data == decoded_data

description link:
https://github.com/openstack/pyeclib/blob/master/pyeclib/ec_iface.py

installation link:
[per installare andate sulla pagina officiale di python pyeclib](https://pypi.org/project/pyeclib/)
