#!/usr/bin/env python3

import scapy.all as scapy
import socket
from collections import defaultdict
import os
import pprint


def proto_name_by_num(proto_num):
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"


# Flow tracker
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.packets_sent = 0
        self.packets_received = 0
        self.size_of_sent_data = 0
        self.size_of_received_data = 0

    def __str__(self):
        return f"""
Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}
Protocol: {self.proto}
Packets Sent: {self.packets_sent}
Packets Received: {self.packets_received}
Sent Data (bytes): {self.size_of_sent_data}
Received Data (bytes): {self.size_of_received_data}
"""


# Dictionary to store flows
flows = defaultdict(Flow)


# Function to create flow key based on 5-tuple
def create_flow_key(packet):
    # Extract necessary information for the 5-tuple
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    # proto_num = packet[scapy.IP].proto
    # proto = proto_name_by_num(proto_num)
    proto = packet.payload.layers()[1].__name__
    src_port = 0
    dst_port = 0

    # For protocols like TCP and UDP, ports are important
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        src_port = packet.sport
        dst_port = packet.dport

    # Ensure the lower IP and port always come first in the flow key
    if (src_ip, src_port) > (dst_ip, dst_port):
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port

    return (src_ip, dst_ip, src_port, dst_port, proto)


# Packet handler function
def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        # Create a unique flow key based on the 5-tuple
        flow_key = create_flow_key(packet)

        # Check if this flow already exists
        if flow_key not in flows:
            flows[flow_key] = Flow(*flow_key)

        # Determine whether the packet is sent or received
        if packet[scapy.IP].src == flows[flow_key].src_ip:
            flows[flow_key].packets_sent += 1
        else:
            flows[flow_key].packets_received += 1

        # Output flow information in real-time
        os.system("clear")  # Clear the console for better readability
        print(f"Updated Flow Information:\n{flows[flow_key]}")
        # print(dict(flows))

        # Prints the nicely formatted dictionary
        pprint.pprint(dict(flows))


# Function to list available interfaces and let user choose one
def choose_interface():
    interfaces = scapy.get_if_list()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")

    while True:
        choice = input(f"Choose the interface [0-{len(interfaces)-1}]: ")
        if choice.isdigit() and int(choice) in range(len(interfaces)):
            return interfaces[int(choice)]
        else:
            print("Invalid choice. Please try again.")


# Main function to start sniffing
def start_sniffing():
    interface = choose_interface()
    print(f"Sniffing on interface: {interface}")
    scapy.sniff(iface=interface, prn=packet_handler, store=False)


if __name__ == "__main__":
    start_sniffing()
