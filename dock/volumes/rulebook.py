# [x] out-going flows that sent above 1500 bytes.
# [ ] in-going and out-going flows to and from blacklisted ports.
# [ ] blacklisted protocols
# [ ] blacklisted ips
# [x] http request without an earlier dns query/response
# [x] protocol and port not matching
# [ ] dfjyjdtjrghfdshnfnhjdthrilvegfuhvoiwesvkiehbgvwiweskeilgbdkjbndkjbnldfgkbjndfkjgbodgpsuhvfikjvcwsijv.catvids.com
# [ ] ICMP tunneling


import pprint
import scapy.all as scapy
import packet_handler as ph
from collections import defaultdict

# Dictionary to store flows
flows = defaultdict(ph.Flow)
dns_cached_ips = set()

port_to_proto = {
    7: 'Echo',
    20: 'FTP',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    69: 'TFTP',
    80: 'HTTP',
    88: 'Kerberos',
    110: 'POP3',
    123: 'NTP',
    137: 'NBNS',
    143: 'IMAP',
    161: 'SNMP',
    194: 'IRC',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    464: 'Kerberos',
    547: 'DHCPv6',
    596: 'SMSD',
    636: 'LDAP',
    1720: 'H.323',
    3389: 'RDP',
    5060: 'SIP',
    5061: 'SIP'
}

bigger_dict = {
    7:   'Echo',
    19:  'CHARGEN',
    20:  'FTP-data',
    21:  'FTP',
    22:  'SSH',
    23:  'Telnet',
    25:  'SMTP',
    42:  'WINS Replication',
    43:  'WHOIS',
    49:  'TACACS',
    53:  'DNS',
    67:  'DHCP',
    68:  'DHCP',
    69:  'TFTP',
    70:  'Gopher',
    79:  'Finger',
    80:  'HTTP',
    88:  'Kerberos',
    102: 'Microsoft',
    110: 'POP3',
    113: 'Ident',
    119: 'NNTP',
    123: 'NTP',
    135: 'Microsoft',
    137: 'NBNS',
    138: 'NetBIOS-dgm',
    139: 'NetBIOS-ssn',
    143: 'IMAP',
    161: 'SNMP-agents',
    162: 'SNMP-trap',
    177: 'XDMCP',
    179: 'BGP',
    194: 'IRC',
    201: 'AppleTalk',
    264: 'BGMP',
    318: 'TSP',
    381: 'HP Openview',
    383: 'HP Openview',
    389: 'LDAP',
    427: 'SLP',
    443: 'HTTPS',
    445: 'SMB',
    464: 'Kerberos',
    465: 'SMTP',
    497: 'Dantz Retrospect',
    500: 'IPSec',
    512: 'rexec',
    513: 'rlogin',
    514: 'syslog',
    515: 'LPD',
    520: 'RIP',
    521: 'RIPng',
    540: 'UUCP',
    548: 'AFP',
    554: 'RTSP',
    546: 'DHCPv6',
    547: 'DHCPv6',
    560: 'rmonitor',
    563: 'NNTP',
    587: 'SMTP',
    591: 'FileMaker',
    593: 'DCOM',
    596: 'SMSD',
    631: 'IPP',
    636: 'LDAP',
    639: 'MSDP',
    646: 'LDP',
    691: 'Microsoft Exchange',
    860: 'iSCSI',
    873: 'rsync',
    902: 'VMware Server',
    989: 'FTPS',
    990: 'FTPS',
    993: 'IMAPS',
    995: 'POP3S'
}

local_protocols = {
    137: 'NBNS',
    5355: 'LLMNR'
}

ip_blacklist = {
    '8.8.8.8',
    '8.8.4.4',
    '1.1.1.1',
    '1.0.0.1'
}

port_blacklist = {
    1234,
    2345
}

dns_domains = defaultdict(int)
dns_subdomains = defaultdict(set)


def add_to_dns_cached_ips(packet, key):
    if key[-1] != 'DNS':
        return
    for x in range(packet[scapy.DNS].ancount):
        dns_resp_ip_addr = packet[scapy.DNSRR][x].rdata
        domain_name = packet[scapy.DNSRR][x].rrname
        # print(f'DNS Response: {domain_name} -> {dns_resp_ip_addr}')
        domain_name = domain_name.decode('utf-8').rstrip('.')
        tld = '.'.join(domain_name.split('.')[-2:])
        print(f'{tld=}')
        subdomain = '.'.join(domain_name.split('.')[:-2])
        print(f'{subdomain=}')
        pprint.pprint(f'{dict(dns_domains)=}')
        dns_domains[tld] += 1
        dns_subdomains[tld].add(subdomain)
        if not isinstance(dns_resp_ip_addr, str):
            continue
        dns_cached_ips.add(dns_resp_ip_addr)


def check_dns_tunneling(packet):
    for x in range(packet[scapy.DNS].ancount):
        domain_name = packet[scapy.DNSRR][x].rrname
        # print(f'DNS Response: {domain_name} -> {dns_resp_ip_addr}')
        domain_name = domain_name.decode('utf-8').rstrip('.')
        tld = '.'.join(domain_name.split('.')[-2:])
        print(f'{tld=}')
        if dns_domains[tld] > 15:
            for subdomain in dns_subdomains[tld]:
                if len(subdomain) > 30:
                    return True
    return False


def check_invalid_packet_size(packet):
    return not (50 < len(packet) < 6000)


def check_invalid_http_request(packet):
    return packet.haslayer(HTTP) and packet[scapy.IP].dst not in dns_cached_ips


def check_matching_port_to_proto(packet):
    dst_port = 0
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        dst_port = packet.dport
    proto = packet.payload.layers()[-1].__name__
    if proto == 'Raw' or proto == 'Padding':
        proto = packet.payload.layers()[-2].__name__
    if dst_port == 443 or dst_port == 80 and proto == 'UDP' or proto == 'TCP':
        return False
    if dst_port not in port_to_proto:
        return False
    return port_to_proto[dst_port] not in proto and proto not in port_to_proto[dst_port]


def check_suspicious(packet, key, from_pcap=False) -> bool:
    sus_flag = False
    sus_str = ''
    routes = set()
    proto = key[-1]
    for line in scapy.read_routes():
        routes.add(line[4])
    if not from_pcap:
        if key[0] not in routes:
            return sus_flag, sus_str

    if check_invalid_packet_size(packet):
        sus_flag = True
        sus_str += f'Invalid packet size: {len(packet)}\n'
    if check_invalid_http_request(packet):
        sus_flag = True
        sus_str += 'HTTP without prior DNS request\n'
    if check_matching_port_to_proto(packet):
        sus_flag = True
        sus_str += f'Port {packet.dport} does not match to {proto} protocol\n'
    if proto == 'DNS' and check_dns_tunneling(packet):
        sus_flag = True
        sus_str += 'DNS tunneling detected\n'
    return sus_flag, sus_str


def suspicious_flow(flow_key: tuple) -> bool:
    # sus_flag = False
    ...
