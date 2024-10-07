import pytest
import rulebook as rb
import scapy.all as scapy
import packet_handler as ph


def test_bad_icmp_tunneling():
    flag = False
    for packet in scapy.PcapReader('volumes/BadICMP.pcap'):
        flag = flag or rb.check_icmp_tunneling(packet)
    assert flag


def test_good_icmp_tunneling():
    flag = False
    for packet in scapy.PcapReader('volumes/GoodICMP.pcap'):
        flag = flag or rb.check_icmp_tunneling(packet)
    assert not flag


def test_blacklisted_port():
    packet = scapy.Ether()/scapy.IP(dst='8.8.8.8')/scapy.TCP(dport=9012, flags='S')
    assert rb.check_for_blacklisted_port(packet)


def test_blacklisted_proto():
    flag = False
    for packet in scapy.PcapReader('volumes/LLMNR.pcap'):
        flag = flag or rb.check_for_blacklisted_proto(packet)
    assert not flag


def test_blacklisted_ip():
    flag = False
    for packet in scapy.PcapReader('volumes/mypcap2.pcap'):
        flag = flag or rb.check_for_blacklisted_ip(packet)
    assert flag


def test_dns_tunneling():
    flag = False
    for packet in scapy.PcapReader('volumes/Base64.pcap'):
        flag = flag or rb.check_icmp_tunneling(packet)
    assert flag


def test_invalid_packet_size():
    packet = scapy.IP(dst="192.168.1.1")/scapy.TCP(dport=443)/scapy.Raw(scapy.RandString(size=10_000))
    assert rb.check_invalid_packet_size(packet)


def test_invalid_http_request():
    scapy.load_layer('http')
    flag = False
    for packet in scapy.PcapReader('volumes/mypcap2.pcap'):
        flag = flag or rb.check_invalid_http_request(packet)
    assert flag


def test_matching_port_to_proto():
    packet = scapy.Ether()/scapy.IP(dst='8.8.8.8')/scapy.TCP(dport=9012, flags='S')
    assert not rb.check_matching_port_to_proto(packet)
