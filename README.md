# Network Intrusion Detection System (IDS)

A comprehensive network intrusion detection system with a graphical user interface built using Python, Flet, and Scapy. This system monitors network traffic in real-time and detects various types of suspicious activities and potential security threats.

## Features

### Real-time Network Monitoring
- Live packet capture from network interfaces
- PCAP file analysis support
- Flow-based traffic analysis using 5-tuple identification (source IP, destination IP, source port, destination port, protocol)

### Threat Detection Capabilities
- **ICMP Tunneling Detection**: Identifies suspicious ICMP traffic patterns
- **DNS Tunneling Detection**: Detects potential data exfiltration through DNS queries
- **HTTP without DNS**: Flags HTTP requests without prior DNS resolution
- **Protocol-Port Mismatch**: Identifies traffic using incorrect ports for protocols
- **Blacklisted Entities**: Monitors for blacklisted IPs, ports, and protocols
- **Oversized Packets**: Detects abnormally large packets (>6000 bytes)
- **High-volume Flows**: Identifies flows exceeding data thresholds

### Interactive GUI
- Dark/Light theme toggle
- Network interface selection
- Advanced filtering options (IP addresses, ports, protocols, direction)
- Real-time flow visualization
- Suspicious activity alerts
- PCAP file upload and analysis

## Architecture

The system consists of several key components:

- **`gui.py`**: Main GUI application built with Flet
- **`packet_handler.py`**: Core packet processing and flow management
- **`rulebook.py`**: Detection rules and suspicious activity analysis
- **`test_rulebook.py`**: Unit tests for detection capabilities

## Installation and Setup

### Prerequisites
- Docker and Docker Compose
- Linux environment (recommended)
- For Windows: X Server (VcXsrv) for GUI display

### Linux Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd intrusion-detection-system
```

2. Build and run the Docker containers:
```bash
cd /dock
sudo docker-compose build
sudo docker-compose up
```

### Windows Installation

1. Download and install [VcXsrv Windows X Server](https://sourceforge.net/projects/vcxsrv/)

2. Configure XLaunch:
   - Select "Full Screen" option
   - Select "Start no client" option
   - Mark "Disable access control" box
   - Click Finish

3. Set environment variables:
```bash
export DISPLAY=$(ip route list default | awk '{print $3}'):0
export LIBGL_ALWAYS_INDIRECT=1
```

4. Build and run:
```bash
sudo docker-compose build
sudo docker-compose up
```

## Usage

### Real-time Monitoring

1. Launch the application
2. Select a network interface from the dropdown menu
3. Click "Start Sniffing" to begin real-time packet capture
4. Monitor the flow list and alerts for suspicious activities

### PCAP Analysis

1. Click "Pick files" to upload a PCAP file
2. Select a `.pcap` or `.pcapng` file
3. The system will automatically analyze all packets and display results

### Filtering and Analysis

Use the filter controls to focus on specific traffic:
- **Source/Destination IP**: Filter by specific IP addresses
- **Source/Destination Port**: Filter by port numbers
- **Protocol**: Filter by network protocol
- **Direction**: Filter by traffic direction (incoming/outgoing)

## Detection Rules

### ICMP Tunneling
- Detects ICMP packets with payloads >64 bytes
- Monitors for excessive ICMP requests (>20 to same destination)

### DNS Tunneling
- Identifies domains with excessive queries (>15)
- Detects suspiciously long subdomains (>30 characters)

### Blacklisted Entities

**Ports**: 1337, 1234, 2345, 3456, 4567, 5678, 6789, 7890, 8901, 9012, 6969

**Protocols**: NBNS, ARP, LLMNR (local protocols)

**IPs**: Loopback, broadcast, and specific threat IPs

### Protocol-Port Validation
Ensures traffic uses appropriate ports for protocols based on standard port assignments.

## Testing

Run the test suite to verify detection capabilities:

```bash
python -m pytest volumes/test_rulebook.py -v
```

Tests cover:
- ICMP tunneling detection
- Blacklisted entity detection
- DNS tunneling identification
- Protocol-port mismatch validation
- Packet size validation

## Dependencies

- **Flet**: Modern GUI framework for Python
- **Scapy**: Powerful packet manipulation library
- **Docker**: Containerization platform

## Configuration

The system uses several configuration files:

- **`docker-compose.yml`**: Container orchestration
- **`flet-dock/Dockerfile`**: Application container setup
- **`requirements.txt`**: Python dependencies
- **`.gitignore`**: Version control exclusions

## Security Considerations

- Requires elevated privileges for packet capture
- Runs in privileged Docker container for network access
- Designed for authorized network monitoring only
- Ensure compliance with local network monitoring policies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new detection rules
4. Submit a pull request

## License

This project is provided for educational and authorized security monitoring purposes. Ensure compliance with applicable laws and regulations when deploying in production environments.

## Troubleshooting

### Common Issues

**GUI not displaying on Windows**: Ensure X Server is running and DISPLAY variable is set correctly

**Permission denied errors**: Verify Docker is running with appropriate privileges

**Network interface not found**: Check available interfaces with `ip link show` or similar commands

**Container build failures**: Ensure Docker has sufficient resources and internet connectivity

### Support

For issues and questions, please check the project documentation or submit an issue in the repository.
