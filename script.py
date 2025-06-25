from scapy.all import *
from typing import Callable, Union, Any

IF_FROM = "enp0s8"
IF_TO = "enp0s9"
IF_FROM_MAC = "08:00:27:3c:d9:98" 

def forwarding(pkt: Any) -> Any:
    """
    A wrapper function for forwarded packets

    :param pkt: The packet to be forwarded
    :return: The packet to be forwarded ( changed / unchanged )
    """
    if pkt.layers()[0] != scapy.layers.l2.Ether:
        return False
    if len(pkt.layers()) <= 2:
            return False

    pkt.src = MY_MAC 
    return pkt


def bridge_ifs(if1: NetworkInterface, if2: NetworkInterface, xfrm12: Callable = None, xfrm21: Callable  = None) -> None:
    """
    Apply functions on packets from two interfaces, and decide if to forward to eachother.

    :param if1: The first interface to bridge with
    :param if2: The second interface to bridge with
    :param xfrm12: the callable to apply to the packet coming from if1
    :param xfrm21: the callable to apply to the packet coming from if2
    """
    bridge_and_sniff(if1, if2, xfrm12, xfrm21)


if __name__ == '__main__':
    bridge_ifs(IF_FROM, IF_TO, xfrm12=forwarding)
