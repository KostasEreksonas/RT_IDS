#!/usr/bin/env python3

from scapy.all import *

def dns_sniffer(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP):
        ip_src = packet[IP].src
        dns_query = packet[DNS].qd.qname.decode('utf-8')
        print(f"DNS Query from {ip_src}: {dns_query}")
# Starting our DNS sniffer
sniff(filter="udp port 53", prn=dns_sniffer, store=0)
