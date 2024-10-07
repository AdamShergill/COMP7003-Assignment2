import argparse
from scapy.all import sniff

# Helper function to convert hex to decimal
def hex_to_decimal(hex_value):
    return int(hex_value, 16)

# Helper function to convert hex to binary
def hex_to_binary(hex_value):
    binary_value = bin(int(hex_value, 16))[2:]  # Remove the "0b" prefix from binary
    return binary_value.zfill(8 * (len(hex_value) // 2))  # Ensure padding for full bytes

# Convert hex to binary and add spaces for easier reading (for flags)
def hex_to_binary_with_spaces(hex_value):
    binary_value = hex_to_binary(hex_value)
    return ' '.join([binary_value[i:i+4] for i in range(0, len(binary_value), 4)])

# Extract first three bits of a binary string (used for flags)
def get_first_three_bits(binary_value):
    return binary_value[:3]

# Check if a bit is set (1) or not (0)
def check_bit(bit):
    return "Set" if bit == '1' else "Not Set"

def hex_to_ip(hex_value):
    return '.'.join(str(hex_to_decimal(hex_value[i:i+2])) for i in range(0, len(hex_value), 2))


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

def parse_ipv4_packet(hex_data):
    print("Parsing IPv4 packet...")

    # Extract IPv4 header fields
    version_ihl = hex_data[0:2]  # Version + IHL (1 byte)
    tos = hex_data[2:4]  # Type of Service (1 byte)
    total_length = hex_data[4:8]  # Total Length (2 bytes)
    identification = hex_data[8:12]  # Identification (2 bytes)
    flags_fragment_offset = hex_data[12:16]  # Flags + Fragment Offset (2 bytes)
    ttl = hex_data[16:18]  # Time to Live (1 byte)
    protocol = hex_data[18:20]  # Protocol (1 byte)
    checksum = hex_data[20:24]  # Header Checksum (2 bytes)
    source_ip = hex_data[24:32]  # Source IP Address (4 bytes)
    destination_ip = hex_data[32:40]  # Destination IP Address (4 bytes)

    # Print out the IPv4 header fields
    print(f"Version/IHL (Hex): {version_ihl} -> Human Readable: {hex_to_decimal(version_ihl)}")
    print(f"TOS (Hex): {tos} -> Human Readable: {hex_to_decimal(tos)}")
    print(f"Total Length (Hex): {total_length} -> Human Readable: {hex_to_decimal(total_length)}")
    print(f"Identification (Hex): {identification} -> Human Readable: {hex_to_decimal(identification)}")

    # Extract and print flags
    flags_binary = hex_to_binary_with_spaces(flags_fragment_offset)
    three_flag_bits = get_first_three_bits(flags_binary)
    print(f"Flags + Fragment Offset (Hex): {flags_fragment_offset} -> {flags_binary}")
    print(f"    - Reserved: {check_bit(three_flag_bits[0])}")
    print(f"    - Don't Fragment: {check_bit(three_flag_bits[1])}")
    print(f"    - More Fragments: {check_bit(three_flag_bits[2])}")

    print(f"TTL (Hex): {ttl} -> Human Readable: {hex_to_decimal(ttl)}")
    print(f"Protocol (Hex): {protocol} -> Human Readable: {hex_to_decimal(protocol)}")
    print(f"Checksum (Hex): {checksum} -> Human Readable: {hex_to_decimal(checksum)}")
    print(f"Source IP: {hex_to_ip(source_ip)}")
    print(f"Destination IP: {hex_to_ip(destination_ip)}")

    # Check for TCP or UDP and call the respective function
    protocol_value = hex_to_decimal(protocol)
    if protocol_value == 6:  # TCP
        print("This is a TCP packet.")
        parse_tcp_packet(hex_data[40:])  # Pass the remaining packet to TCP parser
    elif protocol_value == 17:  # UDP
        print("This is a UDP packet.")
        parse_udp_packet(hex_data[40:])  # Pass the remaining packet to UDP parser
    else:
        print(f"Unknown protocol: {protocol_value}")


def parse_tcp_packet(hex_data):
    print("Parsing TCP packet...")

    # Extract TCP fields
    source_port = hex_data[0:4]  # Source Port (2 bytes)
    dest_port = hex_data[4:8]  # Destination Port (2 bytes)
    seq_number = hex_data[8:16]  # Sequence Number (4 bytes)
    ack_number = hex_data[16:24]  # Acknowledgment Number (4 bytes)
    data_offset_flags = hex_data[24:28]  # Data Offset + Flags (2 bytes)
    window_size = hex_data[28:32]  # Window Size (2 bytes)
    checksum = hex_data[32:36]  # Checksum (2 bytes)
    urgent_pointer = hex_data[36:40]  # Urgent Pointer (2 bytes)

    # Convert and print fields
    print(f"Source Port (Hex): {source_port} -> Human Readable: {hex_to_decimal(source_port)}")
    print(f"Destination Port (Hex): {dest_port} -> Human Readable: {hex_to_decimal(dest_port)}")
    print(f"Sequence Number (Hex): {seq_number} -> Human Readable: {hex_to_decimal(seq_number)}")
    print(f"Acknowledgment Number (Hex): {ack_number} -> Human Readable: {hex_to_decimal(ack_number)}")

    # Extract and print flags
    flags_binary = hex_to_binary_with_spaces(data_offset_flags[2:4])  # Last byte contains the flags
    print(f"Flags (Hex): {data_offset_flags[2:4]} -> Binary: {flags_binary}")
    print(f"    - URG: {check_bit(flags_binary[5])}")
    print(f"    - ACK: {check_bit(flags_binary[4])}")
    print(f"    - PSH: {check_bit(flags_binary[3])}")
    print(f"    - RST: {check_bit(flags_binary[2])}")
    print(f"    - SYN: {check_bit(flags_binary[1])}")
    print(f"    - FIN: {check_bit(flags_binary[0])}")

    print(f"Window Size (Hex): {window_size} -> Human Readable: {hex_to_decimal(window_size)}")
    print(f"Checksum (Hex): {checksum} -> Human Readable: {hex_to_decimal(checksum)}")
    print(f"Urgent Pointer (Hex): {urgent_pointer} -> Human Readable: {hex_to_decimal(urgent_pointer)}")


def parse_udp_packet(hex_data):
    print("Parsing UDP packet")

    # Extract UDP fields
    source_port = hex_data[0:4]  # Source Port (2 bytes)
    dest_port = hex_data[4:8]  # Destination Port (2 bytes)
    length = hex_data[8:12]  # Length (2 bytes)
    checksum = hex_data[12:16]  # Checksum (2 bytes)

    # Convert and print fields
    print(f"Source Port (Hex): {source_port} -> Human Readable: {hex_to_decimal(source_port)}")
    print(f"Destination Port (Hex): {dest_port} -> Human Readable: {hex_to_decimal(dest_port)}")
    print(f"Length (Hex): {length} -> Human Readable: {hex_to_decimal(length)}")
    print(f"Checksum (Hex): {checksum} -> Human Readable: {hex_to_decimal(checksum)}")


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

