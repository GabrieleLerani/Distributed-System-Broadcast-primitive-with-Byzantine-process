1)Install python 3.7 on linux

	sudo add-apt-repository ppa:deadsnakes/ppa
	sudo apt-get update
	sudo apt install python3.7-distutils

2)Install pip if it doesn't exist yet

	sudo apt install python3-pip

3)Install distutils package for python3.7

	sudo apt install python3.7-distutils

Docker RabbitMQ

1)Start the Docker with RabbitMQ

	docker run -d -p <ip_address>:5672:5672 -p 15672:15672 rabbitmq:3.8.15-rc.2-management
