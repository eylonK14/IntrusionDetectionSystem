import scapy.all as scapy
# import socket


# def proto_name_by_num(proto_num):
#     for name, num in vars(socket).items():
#         if name.startswith("IPPROTO") and proto_num == num:
#             return name[8:]
#     return "Protocol not found"


# Flow tracker
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.outgoing = None
        self.packets_sent = 0
        self.size_of_sent_data = 0

    def __str__(self):
        return f"""
Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}
Protocol: {self.proto}
Flow direction: {'outgoing' if self.outgoing else 'ingoing'}
Packets Sent: {self.packets_sent}
Sent Data (bytes): {self.size_of_sent_data}
"""


# Function to get the size of the payload in bytes
def get_payload_size(packet):
    # Check if there's a raw payload (TCP/UDP/other data)
    if packet.haslayer(scapy.Raw):
        return len(packet[scapy.Raw].load)
    return 0


# Function to create flow key based on 5-tuple
def create_flow_key(packet):
    # Extract necessary information for the 5-tuple
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    # proto_num = packet[scapy.IP].proto
    # proto = proto_name_by_num(proto_num)
    proto = packet.payload.layers()[-1].__name__
    if proto == 'Raw' or proto == 'Padding':
        proto = packet.payload.layers()[-2].__name__
    src_port = 0
    dst_port = 0

    # For protocols like TCP and UDP, ports are important
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        src_port = packet.sport
        dst_port = packet.dport

    return (src_ip, dst_ip, src_port, dst_port, proto)
