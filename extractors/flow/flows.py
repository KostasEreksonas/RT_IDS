#!/usr/bin/env python3

import psutil
from scapy.all import *

class PacketInfo:
    """
    Collect packet metadata to generate statistical flow features
    """
    def __init__(self):
        """Initialize packet metadata extractor"""
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.protocol = ""
        self.timestamp = 0
        self.pid = None
        self.p_name = ""

    def set_source_ip(self, packet):
        """Set source IP address"""
        if packet.haslayer(IP):
            self.src_ip = packet[IP].src

    def get_source_ip(self) -> str:
        self.src_ip

    def set_destination_ip(self, packet):
        """Set destination IP address"""
        if packet.haslayer(IP):
            self.dst_ip = packet[IP].dst
    
    def get_destination_ip(self) -> str:
        self.dst_ip

    def set_source_port(self, packet):
        """Set source port"""
        if packet.haslayer(TCP):
            self.src_port = packet[TCP].sport
        elif packet.haslayer(UDP):
            self.src_port = packet[UDP].sport

        if self.pid is None and self.p_name == "":
            connections = psutil.net_connections()
            for con in connections:
                if (con.laddr.port - self.src_port == 0.0) or (con.laddr.port - self.dst_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    def get_source_port(self) -> int:
        return self.src_port

    def set_destination_port(self, packet):
        """Set destination port"""
        if packet.haslayer(TCP):
            self.dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            self.dst_port = packet[UDP].dport

    def get_destination_port(self) -> int:
        return self.dst_port

    def set_protocol(self, packet):
        """Set protocol info"""
        protocol = packet[IP].proto
        if protocol == 1:
            self.protocol = "ICMP"
        elif protocol == 6:
            self.protocol = "TCP"
        elif protocol == 17:
            self.protocol = "UDP"

    def get_protocol(self) -> str:
        return self.protocol

    def set_timestamp(self, packet):
        """Set timestamp of packet"""
        self.timestamp = packet.time

    def get_timestamp(self) -> float:
        return self.timestamp

    def packet_info(self):
        """Collect packet metadata"""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol, self.timestamp, self.pid, self.p_name)

def info(packet):
    p = PacketInfo()
    p.set_source_ip(packet)
    p.set_destination_ip(packet)
    p.set_source_port(packet)
    p.set_destination_port(packet)
    p.set_protocol(packet)
    p.set_timestamp(packet)

    print(p.packet_info())

def main():
    sniff(filter="ip", prn=info, store=False)

if __name__ == "__main__":
    main()
