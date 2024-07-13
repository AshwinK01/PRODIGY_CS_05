from scapy.all import sniff, TCP, IP

# Callback function to process each packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"IP {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport} (Protocol: {proto})")
        else:
            print(f"IP {ip_src} -> {ip_dst} (Protocol: {proto})")

# Sniff the packets
sniff(prn=packet_callback, store=0)
