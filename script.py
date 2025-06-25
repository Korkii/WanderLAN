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
    """
    A wrapper function for forwarded packets

    :param pkt: The packet to be forwarded
    :return: The packet to be forwarded ( changed / unchanged )
    """
    print(f"Layers: {pkt.layers()}")
    if len(pkt.layers()) == 1:
        return False

    pkt.src = THIS_MAC
    
    # no port, we can simply return
    if len(pkt.layers()) == 2 or pkt.layers()[1] == scapy.layers.l2.ARP:
        return False

    if pkt.layers()[2] == scapy.layers.inet.ICMP:
        return False

    rand_port = randint(MIN_NAT_PORT, MAX_NAT_PORT)

    nat_table[(THIS_IP, rand_port)] = (pkt[1].src, pkt[2].sport)
     
    pkt[1].src = THIS_IP
    pkt[2].sport = rand_port
    return pkt

def forward_in(pkt):
    """
    A wrapper function for incoming packets

    :param pkt: The packet to be forwarded inside
    :return: The packet for be forwarded inside ( changed )
    """
    print(f"Layers: {pkt.layers()}")
    entry = nat_table.get((pkt[1].dst, pkt[2].dport))
    if not entry:
        return False

    pkt[1].dst = entry[0]
    pkt[2].dport = entry[1]
    del nat_table[(pkt[1].dst, pkt[2].dport)]
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
