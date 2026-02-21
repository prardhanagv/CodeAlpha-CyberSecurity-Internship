from scapy.all import *

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        protocol = packet[IP].proto
        
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = "Other"

        print(f"\nPacket #{packet_count}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {proto_name}")
        print("-" * 50)

print("Starting Network Sniffer...")
sniff(prn=packet_callback, store=0)
