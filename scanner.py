import argparse
from scapy.all import sniff

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")

    if ether_type == "0806": #ARP packet.
        parse_arp_packet(hex_data[28:])
    elif ether_type == "0800":  # IPv4 packet.
        parse_ipv4_packet(hex_data[28:])
    else:
        print("Unsupported EtherType")

# Placeholder function for parsing arp packet.
def parse_arp_packet(hex_data):
    print("Parsing ARP packet...")

# Placeholder function for parsing ipv4 packet which will then have to check header. For TCP or UDP.
def parse_ipv4_packet(hex_data):
    print("Parsing IPv4 packet...")
    protocol = hex_data[18:20]  # Check protocol type in IPv4 header
    if protocol == "06":
        parse_tcp_packet(hex_data[40:])
    elif protocol == "11":
        parse_udp_packet(hex_data[40:])

#Placeholder function for parsing tcp packet.
def parse_tcp_packet(hex_data):
    print("Parsing TCP packet...")

#Placeholder function for parsing udp packet.
def parse_udp_packet(hex_data):
    print("Parsing UDP packet...")

## Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")
    parse_ethernet_header(hex_data)

    # Returning False to stop after processing the first packet
    return False


# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter=None):
    print(f"Starting packet capture on {interface} with filter: {capture_filter if capture_filter else 'None'}")

    # If no filter is provided, capture the first packet without any filter
    sniff(iface=interface, filter=capture_filter if capture_filter else None, prn=packet_callback, count=1)


# Command-line argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument('interface', help="Network interface to capture packets (e.g., eth0, wlo1)")
    parser.add_argument('--filter', help="BPF filter (e.g., arp, tcp port 80)")

    args = parser.parse_args()

    # Capture packets based on interface and filter (if provided)
    capture_packets(args.interface, args.filter)

