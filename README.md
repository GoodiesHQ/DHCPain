# DHCPain

DHCPain is a simple, no-nonsense DHCP attack toolkit built in Scapy for Python3. It is capable of locating all DHCP servers on the network as well as exhausting DHCP scopes by responding to DHCP Offer messages.

### Purpose
Some attack utilities either do not work with the current version of Scapy (such as [DHCPig](https://github.com/kamorin/DHCPig)), or only floods the network with DHCP Discover packets without properly responding to DHCP Offer messages. This tool is simple and fixes both of these issues.


### Usage

	usage: dhcpain.py 	--iface IFACE
				[--threads THREADS=1]
				[--delay DELAY=1.0]
				[-h/--help]

	required arguments:
	  --iface IFACE, -i IFACE
	                        Interface name

	optional arguments:
	  -h, --help            show this help message and exit
	  --threads THREADS, -t THREADS
	                        Number of concurrent threads
	  --delay DELAY, -d DELAY
	                        Delay between messages per thread

### Example
![Attacker Side](https://i.imgur.com/f1UxsF8.png)
![DHCP Server](https://i.imgur.com/pv6czkO.png)
