#!/usr/bin/env python3

from scapy.all import *
from PacketInfo import PacketInfo

flow_cache = {}

class FlowRecord:
    """Generate flow records and compute statistical features from aggregated packet metadata"""
    def __init__(self, flow_key, packet_key):
        """
        Initialize new flow record
        
        Args:
            flow_key - flow key, sorted 5-tuple
            packet_key - a 5-tuple information of a given packet. Used to determine flow direction.
        """
        self.flow_key = flow_key
        self.packet_key = packet_key
        self.src_ip = self.packet_key[0]
        self.dst_ip = self.packet_key[1]
        self.src_port = self.packet_key[2]
        self.dst_port = self.packet_key[3]
        self.protocol = self.packet_key[4]

    def get_original_flow_key(self):
        """Reconstruct original (unsorted) flow key"""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    def get_packet_key(self):
        """Return a 5-tuple key of a current packet"""
        return self.packet_key

def sort_key(key):
    """Normalize 5-tuple by sorting IP addresses and ports"""
    src_ip = key[0]
    dst_ip = key[1]
    src_port = key[2]
    dst_port = key[3]
    protocol = key[4]

    src = (src_ip, src_port)
    dst = (dst_ip, dst_port)

    if src < dst:
        return (src[0], dst[0], src[1], dst[1], protocol)
    else:
        return (dst[0], src[0], dst[1], src[1], protocol)

def info(packet):
    if packet.haslayer(IP):
        p = PacketInfo()
        p.set_source_ip(packet)
        p.set_destination_ip(packet)
        p.set_source_port(packet)
        p.set_destination_port(packet)
        p.set_protocol(packet)
        p.set_timestamp(packet)
        p.set_packet_size(packet)
        p.set_header_size(packet)
        p.set_payload_size(packet)
        p.set_window_size(packet)
        p.set_FIN_flag(packet)
        p.set_SYN_flag(packet)
        p.set_RST_flag(packet)
        p.set_PSH_flag(packet)
        p.set_ACK_flag(packet)
        p.set_URG_flag(packet)
        p.set_CWE_flag(packet)
        p.set_ECE_flag(packet)

        # Construct a 5-tuple
        src_ip = p.get_source_ip()
        dst_ip = p.get_destination_ip()
        src_port = p.get_source_port()
        dst_port = p.get_destination_port()
        protocol = p.get_protocol()

        packet_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        flow_key = sort_key(packet_key)
        
        if flow_key in flow_cache.keys():
            original_key = flow_cache[flow_key].get_original_flow_key()
            packet_key = flow_cache[flow_key].get_packet_key()
            print(f"{original_key}; {packet_key}")
        else:
            flow_cache[flow_key] = FlowRecord(flow_key, packet_key)

def main():
    sniff(filter="ip", prn=info, store=False)

if __name__ =="__main__":
    main()
