#!/usr/bin/env python3

from scapy.all import *

def extract_dns_metadata(packet):
    metadata = {}
    
    # Timestamp
    metadata['timestamp'] = packet.time
    metadata['readable_time'] = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')

    if packet.haslayer(IP):
        metadata['src_ip'] = packet[IP].src
        metadata['dst_ip'] = packet[IP].dst
        metadata['ttl'] = packet[IP].ttl

    if packet.haslayer(DNS):
        dns = packet[DNS]
        metadata['dns_id'] = dns.id
        metadata['qr'] = dns.qr # 0 = query, 1 = response
        metadata['rcode'] = dns.rcode

        # Query information
        if dns.qd:
            metadata['query_name'] = dns.qd.qname.decode()
            metadata['query_type'] = dns.qd.qtype

        # Extract answer records
        if dns.ancount > 0:
            answers = []
            for i in range(dns.ancount):
                answer_record = dns.an[i]
                answers.append({
                    'name': answer_record.rrname.decode(),
                    'type': answer_record.type,
                    'ttl': answer_record.ttl,
                    'rtada': str(answer_record.rdata)
                })
            metadata['answers'] = answers

    return metadata

def process_dns_packet(packet):
    if packet.haslayer(DNS):
        metadata = extract_dns_metadata(packet)
        #print(f"DNS Query: {metadata.get('query_name')}")
        print(metadata)

sniff(filter="udp port 53", prn=process_dns_packet, store=False)
