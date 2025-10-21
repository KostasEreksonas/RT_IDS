#!/usr/bin/env python3

from scapy.all import *
from PacketInfo import PacketInfo

flow_cache = {}

class FlowRecord:
    """Generate flow records and compute statistical features from aggregated packet metadata"""
    def __init__(self, key):
        """
        Initialize new flow record
        
        Args:
            key - flow key
        """
        self.flow_key = key

    def get_flow_key(self):
        return self.flow_key

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

        flow_key = (p.get_source_ip(), p.get_source_port(), p.get_destination_ip(), p.get_destination_port(), p.get_protocol())
        if flow_key in flow_cache.keys():
            print(flow_cache[flow_key].get_flow_key())
        else:
            flow_cache[flow_key] = FlowRecord(flow_key)

def main():
    sniff(filter="ip", prn=info, store=False)

if __name__ =="__main__":
    main()
