import sys
import time
import flow_analysis
from scapy.all import *

def get_network_interface():
    print("Interfaces available:")
    
    for iface in get_if_list():
        print(iface)
        
    interface = input("Choose an interface: ")
    if interface not in get_if_list():
        print("Invalid interface")
        sys.exit(1)

    return interface


def main():
    
    inter = get_network_interface()
    sniffer = AsyncSniffer(prn = flow_analysis.create_five_tuple, iface = inter)
    sniffer.start()
    time.sleep(30)
    result = sniffer.stop()
    print(result)


if __name__ == "__main__":
    main()


