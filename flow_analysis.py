import sys
from scapy.all import IP, TCP, UDP


def create_five_tuple(pkt):
    print(pkt.payload.layers()[0])
    if pkt.haslayer(IP) and pkt.haslayer(pkt.payload.layers()[1]):
        print((
            pkt[IP].src,
            pkt[pkt.payload.layers()[1]].sport,
            pkt[IP].dst,
            pkt[pkt.payload.layers()[1]].dport,
            pkt.payload.layers()[1].__name__
        ))
    if (not pkt.haslayer(TCP) and not pkt.haslayer(UDP)):
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(pkt.payload.layers())
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        sys.exit(1)

    # if TCP in pkt:
    #    print(pkt.payload.layers())
    #    return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, TCP)
    # elif UDP in pkt:
    #    print(pkt.payload.layers()[2])
    #    return (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport, pkt[UDP].sport)
