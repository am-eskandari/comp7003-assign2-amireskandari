import sys
from scapy.all import sniff

# Function to parse Ethernet header from hex data
def parse_ethernet_header(hex_data):
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]

    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))

    print(f"Ethernet Header:")
    print(f"  Destination MAC: {dest_mac_readable}")
    print(f"  Source MAC: {source_mac_readable}")
    print(f"  EtherType: {ether_type}")

# Function to parse ARP header from hex data
def parse_arp_header(hex_data):
    hw_type = hex_data[28:32]
    proto_type = hex_data[32:36]
    hw_size = hex_data[36:38]
    proto_size = hex_data[38:40]
    opcode = hex_data[40:44]
    sender_mac = hex_data[44:56]
    sender_ip = hex_data[56:64]
    target_mac = hex_data[64:76]
    target_ip = hex_data[76:84]

    sender_mac_readable = ':'.join(sender_mac[i:i + 2] for i in range(0, 12, 2))
    sender_ip_readable = '.'.join(str(int(sender_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    target_mac_readable = ':'.join(target_mac[i:i + 2] for i in range(0, 12, 2))
    target_ip_readable = '.'.join(str(int(target_ip[i:i + 2], 16)) for i in range(0, 8, 2))

    print(f"ARP Header:")
    print(f"  Hardware Type: {hw_type}")
    print(f"  Protocol Type: {proto_type}")
    print(f"  Hardware Size: {hw_size}")
    print(f"  Protocol Size: {proto_size}")
    print(f"  Opcode: {opcode}")
    print(f"  Sender MAC: {sender_mac_readable}")
    print(f"  Sender IP: {sender_ip_readable}")
    print(f"  Target MAC: {target_mac_readable}")
    print(f"  Target IP: {target_ip_readable}")

# Function to handle each captured packet
def packet_callback(packet):
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    print(f"Captured Packet (Hex): {hex_data}")
    parse_ethernet_header(hex_data)

    ether_type = hex_data[24:28]
    if ether_type == '0806':  # ARP
        parse_arp_header(hex_data)
    elif ether_type == '0800':  # IPv4
        parse_ipv4_header(hex_data)
    print("-" * 50)

# IPv4 Header Parsing
def parse_ipv4_header(hex_data):
    version_ihl = hex_data[28:30]
    version = version_ihl[0]
    ihl = version_ihl[1]
    total_length = hex_data[32:36]
    protocol = hex_data[46:48]

    print(f"IPv4 Header:")
    print(f"  Version: {version}")
    print(f"  IHL: {ihl}")
    print(f"  Total Length: {total_length}")
    print(f"  Protocol: {protocol}")

    if protocol == '06':  # TCP
        parse_tcp_header(hex_data)
    elif protocol == '11':  # UDP
        parse_udp_header(hex_data)

# TCP Header Parsing
def parse_tcp_header(hex_data):
    src_port = hex_data[68:72]
    dest_port = hex_data[72:76]
    seq_num = hex_data[76:84]
    ack_num = hex_data[84:92]
    offset_reserved_flags = hex_data[92:96]
    flags = offset_reserved_flags[3:]  # Last byte contains the flags
    flags_binary = bin(int(flags, 16))[2:].zfill(8)  # Convert flags to binary

    print(f"TCP Header:")
    print(f"  Source Port: {int(src_port, 16)}")
    print(f"  Destination Port: {int(dest_port, 16)}")
    print(f"  Sequence Number: {int(seq_num, 16)}")
    print(f"  Acknowledgment Number: {int(ack_num, 16)}")
    print(f"  Flags: {flags_binary} (Binary)")

# UDP Header Parsing
def parse_udp_header(hex_data):
    src_port = hex_data[68:72]
    dest_port = hex_data[72:76]

    print(f"UDP Header:")
    print(f"  Source Port: {int(src_port, 16)}")
    print(f"  Destination Port: {int(dest_port, 16)}")

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

# Main function
if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python3 scanner.py <filter> <interface> <packet_count>")
        sys.exit(1)

    filter_arg = sys.argv[1]
    interface = sys.argv[2]
    packet_count = int(sys.argv[3])

    capture_packets(interface, filter_arg, packet_count)
