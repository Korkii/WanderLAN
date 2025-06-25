from scapy.all import *
from typing import Callable
from random import randint

IF_FROM = "enp0s8"
IF_TO = "enp0s9"
THIS_IP = "192.168.56.101"
THIS_MAC = "08:00:27:3c:d9:98"
nat_table = {}
MIN_NAT_PORT = 49152 
MAX_NAT_PORT = 65535


def forward_out(pkt):
    pkt = forwarding(pkt)
    if not pkt:
        return False

    # no port, we can simply return
    if len(pkt.layers()) == 2:
        return pkt

    rand_port = randint(MIN_NAT_PORT, MAX_NAT_PORT)

    nat_table[(THIS_IP, rand_port)] = (pkt[1].src, pkt[2].sport)
    

def forward_in(pkt):
    entry = nat_table.get((pkt[1].dst, pkt[2].dport))
    if not entry:
        return False

    pkt[1].dst = entry[0]
    pkt[2].dport = entry[1]

    return pkt


def forwarding(pkt):
    """
    A wrapper function for forwarded packets

    :param pkt: The packet to be forwarded
    :return: The packet to be forwarded ( changed / unchanged )
    """
    pkt.src = THIS_MAC
    if len(pkt.layers()) > 0:
        pkt[1].src = THIS_IP
    return pkt


def bridge_ifs(if1: NetworkInterface, if2: NetworkInterface, xfrm12: Callable = None, xfrm21: Callable  = None) -> None:
    """
    Bridges between two interfaces

    :param if1: The first interface to bridge with
    :param if2: The second interface to bridge with
    :param xfrm12: the callable to apply to the packet coming from if1
    :param xfrm21: the callable to apply to the packet coming from if2
    """
    bridge_and_sniff(if1, if2, xfrm12, xfrm21)
    print("Done")


if __name__ == '__main__':
    bridge_ifs(IF_FROM, IF_TO, xfrm12=forward_out, xfrm21=forward_in)
