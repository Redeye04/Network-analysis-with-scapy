from scapy.all import rdpcap, IP, TCP, UDP, Ether

def analyze_pcap(file_path):
    print(f"Loading {file_path}...\n")
    
    try:
        # Load the packet capture
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print("Error: PCAP file not found.")
        return

    tcp_count = 0
    udp_count = 0
    other_count = 0
    
    print("--- First 5 Packets Summary ---")
    
    # Iterate through packets
    for i, pkt in enumerate(packets):
        # Print details for the first 5 packets to simulate log parsing
        if i < 5:
            # Check for Layer 2 (Ethernet)
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                
            # Check for Layer 3 (IP)
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                print(f"Packet {i+1}: {src_mac} -> {dst_mac} | IP: {src_ip} -> {dst_ip}")
            else:
                print(f"Packet {i+1}: Non-IP Packet (L2 only) | {src_mac} -> {dst_mac}")

            
        # Tally protocols for diagnostic reporting
        if pkt.haslayer(TCP):
            tcp_count += 1
        elif pkt.haslayer(UDP):
            udp_count += 1
        else:
            other_count += 1

    print("\n--- Network Diagnostic Summary ---")
    print(f"Total Packets Analyzed: {len(packets)}")
    print(f"TCP Packets: {tcp_count}")
    print(f"UDP Packets: {udp_count}")
    print(f"Other/Dropped: {other_count}")

if __name__ == "__main__":
    # Replace with your actual file name
    analyze_pcap("./network_analysis.pcapng")