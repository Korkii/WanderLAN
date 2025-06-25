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

    pkt.src = IF_FROM_MAC 
    return pkt


if __name__ == '__main__':
    bridge_and_sniff(IF_FROM, IF_TO, xfrm12=forwarding)
