# DHCPain

DHCPain is a simple, no-nonsense DHCP attack toolkit built in Scapy for Python3. It is capable of locating all DHCP servers on the network as well as exhausting DHCP scopes by responding to DHCP Offer messages.

### Purpose
Some attack utilities either do not work with the current version of Scapy (such as [DHCPig](https://github.com/kamorin/DHCPig)), or only floods the network with DHCP Discover packets without properly responding to DHCP Offer messages. This tool is simple and fixes both of these issues.


### Setup

	git clone https://github.com/GoodiesHQ/DHCPain

Though it is not required, it is recommended to install DHCPain into a virtual environment.

	python3 -m virtualenv DHCPain
	cd DHCPain
	
	# Linux
	. bin/activate
	
	# Windows
	Scripts\activate.bat
	
Once your environment is ready, simply install the requirements. DHCPain is a standalone python file.

	pip install -r requirements.txt
	python dhcpain.py


### Usage

	usage: dhcpain.py [-h] (--iface IFACE | --list) [--threads THREADS] [--delay DELAY]

	optional arguments:
	  -h, --help            show this help message and exit
	  --iface IFACE, -i IFACE
				Interface name/index
	  --list, -l            List available interfaces
	  --threads THREADS, -t THREADS
				Number of concurrent threads
	  --delay DELAY, -d DELAY
				Delay between messages per thread

### Example (Linux)
With Linux, the common interface name is the only thing necessary for execution:
![Attacker Side](https://i.imgur.com/f1UxsF8.png)
![DHCP Server](https://i.imgur.com/pv6czkO.png)


### Example (Windows)
On Windows, you will need to provide either the complete interface name, or the index. In this case, either of these two commands would operate the same way:

	python dhcpain.py --iface 28
	python dhcpain.py --iface "Intel(R) Dual Band Wireless-AC 8275"

![Windows Interfaces](https://i.imgur.com/kpvYw2d.png)

Once the interface is selected, it will perform as normal:

![Attacker Side](https://i.imgur.com/8kLZFWU.png)
