import pickle
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from scapy.all import *

from classes.PacketInfo import PacketInfo
from classes.FlowFeatures import FlowFeatures

inactivity_check_period = 5 # 5 second periodic check of inactive timeouts of cached flows
inactivity_check_time = time.time() # UNIX timestamp used to determine when to do periodic inactive timeout check

flow_cache = {}

active_timeout = 60 # 60 seconds for active timeout
inactive_timeout = 30 # 30 seconds of inactivity

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
        return src[0], dst[0], src[1], dst[1], protocol
    else:
        return dst[0], src[0], dst[1], src[1], protocol

def classify(stats):
    """Classify given flow record"""
    model_path = "../../models/CIC_IDS_2017/xgb_clf_multiclass.pkl"
    with open(model_path, 'rb') as file:
        model = pickle.load(file)

    scaler = StandardScaler()

    stats = np.asarray(stats)
    stats = stats.reshape(-1, 1)
    stats = scaler.fit_transform(stats)
    stats = stats.reshape(1, -1)

    results = model.predict_proba(stats)
    return results

def info(network_packet):
    global inactivity_check_time

    if network_packet.haslayer(IP):
        p = PacketInfo()
        p.set_source_ip(network_packet)
        p.set_destination_ip(network_packet)
        p.set_source_port(network_packet)
        p.set_destination_port(network_packet)
        p.set_protocol(network_packet)
        p.set_timestamp(network_packet)
        p.set_packet_size(network_packet)
        p.set_header_size(network_packet)
        p.set_payload_size(network_packet)
        p.set_window_size(network_packet)
        p.set_fin_flag(network_packet)
        p.set_syn_flag(network_packet)
        p.set_rst_flag(network_packet)
        p.set_psh_flag(network_packet)
        p.set_ack_flag(network_packet)
        p.set_urg_flag(network_packet)
        p.set_cwe_flag(network_packet)
        p.set_ece_flag(network_packet)

        # Get timestamp of current packet
        current_timestamp = p.get_timestamp()

        # Collect flags into a tuple
        flags = p.get_fin_flag(), \
            p.get_syn_flag(), \
            p.get_rst_flag(), \
            p.get_psh_flag(), \
            p.get_ack_flag(), \
            p.get_urg_flag(), \
            p.get_cwe_flag(), \
            p.get_ece_flag()

        # Get RST and FIN flags for TCP flow termination
        fin = p.get_fin_flag()
        rst = p.get_rst_flag()

        # Current packet data needed to update flow statistics
        packet_size = p.get_packet_size()
        header_size = p.get_header_size()

        # Get flow key
        packet_key = p.get_packet_key()
        flow_key = sort_key(packet_key)

        # Export inactive flows
        if current_timestamp - inactivity_check_time > inactivity_check_period:
            for flow_key in list(flow_cache.keys()):
                last_seen = flow_cache[flow_key].get_last_seen_timestamp()
                if current_timestamp - last_seen > inactive_timeout:
                    stats = flow_cache[flow_key].export_flow_statistics()
                    print(f"{classify(stats)}, Reason: Inactive Timeout")
                    del flow_cache[flow_key]
            inactivity_check_time = current_timestamp

        if flow_key in flow_cache.keys():
            # Check if a flow has expired by the means of active timeout
            initial_timestamp = flow_cache[flow_key].get_initial_timestamp()
            if rst or fin:
                """
                Check if current TCP packet has RST or FIN flag set
                Ignore TCP FIN 4-way handshake for now
                """
                # Update flow statistics based on packet metadata and export the flow
                flow_cache[flow_key].calculate_packet_statistics(packet_key, packet_size)
                flow_cache[flow_key].calculate_per_second_stats(current_timestamp)
                flow_cache[flow_key].calculate_header_length(packet_key, header_size)
                flow_cache[flow_key].calculate_iat_statistics(packet_key, current_timestamp)
                flow_cache[flow_key].count_flag_statistics(network_packet, flags, packet_key)
                stats = flow_cache[flow_key].export_flow_statistics()
                if rst:
                    print(f"{classify(stats)}, Reason: RST")
                elif fin:
                    print(f"{classify(stats)}, Reason: FIN")
                del flow_cache[flow_key]
            elif current_timestamp - initial_timestamp > active_timeout:
                stats = flow_cache[flow_key].export_flow_statistics()
                print(f"{classify(stats)}, Reason: Active Timeout")
                del flow_cache[flow_key]

                # Initialize new flow in place of expired one and update stats based on first packet
                flow_cache[flow_key] = FlowFeatures(flow_key, packet_key, current_timestamp)
                flow_cache[flow_key].calculate_packet_statistics(packet_key, packet_size)
                flow_cache[flow_key].calculate_per_second_stats(current_timestamp)
                flow_cache[flow_key].calculate_header_length(packet_key, header_size)
                flow_cache[flow_key].calculate_iat_statistics(packet_key, current_timestamp)
                flow_cache[flow_key].count_flag_statistics(network_packet, flags, packet_key)
            else:
                # Update existing flow
                flow_cache[flow_key].calculate_packet_statistics(packet_key, packet_size)
                flow_cache[flow_key].calculate_per_second_stats(current_timestamp)
                flow_cache[flow_key].calculate_header_length(packet_key, header_size)
                flow_cache[flow_key].calculate_iat_statistics(packet_key, current_timestamp)
                flow_cache[flow_key].count_flag_statistics(network_packet, flags, packet_key)
                flow_cache[flow_key].update_last_seen_timestamp(current_timestamp)
        else:
            # Initialize new flow record (if no flow record with a given key exists) and update statistics based on first packet
            flow_cache[flow_key] = FlowFeatures(flow_key, packet_key, current_timestamp)
            flow_cache[flow_key].calculate_packet_statistics(packet_key, packet_size)
            flow_cache[flow_key].calculate_per_second_stats(current_timestamp)
            flow_cache[flow_key].calculate_header_length(packet_key, header_size)
            flow_cache[flow_key].calculate_iat_statistics(packet_key, current_timestamp)
            flow_cache[flow_key].count_flag_statistics(network_packet, flags, packet_key)

def main():
    sniff(filter="ip", prn=info, store=False)

if __name__ =="__main__":
    main()