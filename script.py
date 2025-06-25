from scapy.all import *


IF_FROM = "enp0s8"
IF_TO = "enp0s9"


def forwarding(pkt):
    return pkt


def bridge_ifs(if1, if2, xfrm12=None, xfrm21=None):
    bridge_and_sniff(if1, if2, xfrm12, xfrm21)
    print("Done")


if __name__ == '__main__':
    bridge_ifs(IF_FROM, IF_TO, xfrm12=forwarding)
