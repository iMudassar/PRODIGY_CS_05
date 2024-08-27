from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        # Extract the payload data if available
        payload = packet[Raw].load if packet.haslayer(Raw) else "No Payload"

        # Display packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 40)

# Start the packet sniffing process
sniff(prn=packet_callback, store=0)
