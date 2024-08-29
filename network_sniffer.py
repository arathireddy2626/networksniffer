from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f'IP: {ip_src} -> {ip_dst} (TCP) Src Port: {tcp_sport} Dst Port: {tcp_dport}')
        else:
            print(f'IP: {ip_src} -> {ip_dst} (Protocol: {protocol})')

# Sniff packets
sniff(prn=packet_callback, store=0)
