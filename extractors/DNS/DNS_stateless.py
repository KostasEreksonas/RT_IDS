#!/usr/bin/env python3

import re
import csv
import math
import time
import os.path

from scapy.all import *
from collections import Counter

class Stateless:
    """Extract stateless features from DNS packets for CIC-Bell-DNS-EXF-2021 dataset"""
    def __init__(self, feature_dir, feature_csv):
        """
        Initialize static feature extractor
        
        Args:
            feature_dir: Directory to save feature file
            feature_csv: Name of the output csv file
            fieldnames: Saved feature names
        """
        self.feature_dir = feature_dir
        self.feature_csv = feature_csv
        self.fieldnames = [
            'timestamp',
            'src_ip',
            'FQDN_count',
            'subdomain_length',
            'upper',
            'lower',
            'numeric',
            'entropy',
            'special',
            'labels',
            'labels_max',
            'labels_average',
            'longest_word',
            'sld',
            'len',
            'subdomain'
        ]

    @staticmethod
    def extract_query_name(packet) -> Optional[str]:
        """Extract query name from DNS packet"""
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8') if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname
            return qname.rstrip('.')
        return None

    @staticmethod
    def calculate_entropy(domain_string: str) -> float:
        """Calculate Shanon entropy of domain name"""
        if not domain_string:
            return 0.0

        # Count character frequencies
        char_counts = Counter(domain_string)
        length = len(domain_string)

        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log(probability, 2)

        return entropy

    @staticmethod
    def extract_character_features(domain_string: str) -> Dict[str, int]:
        """Extract character count features"""
        features = {
            'upper': sum(1 for c in domain_string if c.isupper()),
            'lower': sum(1 for c in domain_string if c.islower()),
            'numeric': sum(1 for c in domain_string if c.isdigit()),
            'special': sum(1 for c in domain_string if c in '-_=\t'),
            'FQDN_count': len(domain_string)
        }

        return features

    @staticmethod
    def extract_label_features(domain_string: str) -> Dict:
        """Extract label-based features from domain"""
        # Split by dots to get labels
        labels = domain_string.split('.')

        features = {
            'labels': len(labels),
            'labels_max': max(len(label) for label in labels) if labels else 0,
            'labels_average': sum(len(label) for label in labels) / len(labels) if labels else 0
        }

        # Extract subdomain and SLD
        if len(labels) > 2:
            features['sld'] = labels[-2] # Second level domain
            features['subdomain'] = 1 if len(labels) > 2 else 0
            features['subdomain_length'] = sum(len(label) for label in labels[:-2]) if len(labels) > 2 else 0
        else:
            features['sld'] = labels[0] if labels else ''
            features['subdomain'] = 0
            features['subdomain_length'] = 0

        features['len'] = len(domain_string)

        return features

    @staticmethod
    def extract_longest_word(domain_string: str) -> str:
        """Extract longest meaningful word feature"""
        # Remove dots and special characters
        cleaned = re.sub(r'[^a-zA-Z]', ' ', domain_string)
        words = cleaned.split()

        if not words or len(domain_string) == 0:
            return ''

        longest = max(words, key=len) if words else ''
        
        return longest

    @staticmethod
    def get_src_ip(packet) -> Optional[str]:
        """Get source IP address of a DNS query"""
        if packet.haslayer(IP):
            return packet[IP].src
        return None

    def get_stateless_features(self, packet) -> Optional[Dict]:
        """Extract stateless features from DNS packets"""
        query_name = self.extract_query_name(packet)

        if not query_name:
            return None

        features = {}

        # Add timestamp
        features['timestamp'] = time.ctime()

        # Character-based features
        char_features = self.extract_character_features(query_name)
        features.update(char_features)

        # Entropy
        features['entropy'] = self.calculate_entropy(query_name)

        # Label-based features
        label_features = self.extract_label_features(query_name)
        features.update(label_features)

        # Longest word feature
        features['longest_word'] = self.extract_longest_word(query_name)

        # Source IP
        features['src_ip'] = self.get_src_ip(packet)

        return features

    def remap_features(self, packet) -> Optional[Dict]:
        """Remap features so that they are in the same order as in CIC-Bell-DNS-EXF-2021 dataset"""
        features = self.get_stateless_features(packet)
        if not features:
            return None

        remapped_features = {
                'timestamp': features['timestamp'],
                'src_ip': features['src_ip'],
                'FQDN_count': features['FQDN_count'],
                'subdomain_length': features['subdomain_length'],
                'upper': features['upper'],
                'lower': features['lower'],
                'numeric': features['numeric'],
                'entropy': features['entropy'],
                'special': features['special'],
                'labels': features['labels'],
                'labels_max': features['labels_max'],
                'labels_average': features['labels_average'],
                'longest_word': features['longest_word'],
                'sld': features['sld'],
                'len': features['len'],
                'subdomain': features['subdomain']
        }

        return remapped_features

    def save_to_csv(self, remapped_features: Dict) -> None:
        """Write feature rows to csv file"""
        filepath = os.path.join(self.feature_dir, self.feature_csv)
        file_exists = os.path.isfile(filepath)
    
        with open(filepath, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
            
            if not file_exists:
                writer.writeheader()
            
            writer.writerows([remapped_features])

    def process_packet(self, packet) -> Optional[Dict]:
        """
        Process a single packet: extract features and save to CSV
        """
        remapped_features = self.remap_features(packet)

        if remapped_features:
            self.save_to_csv(remapped_features)

        return remapped_features

    def start_sniffing(self, filter_str: str = "udp port 53", save_csv: bool = True) -> None:
        """Start sniffing packets"""
        if save_csv:
            sniff(filter=filter_str, prn=self.process_packet, store=False)  # Print and save to CSV
        else:
            sniff(filter=filter_str, prn=self.remap_features, store=False)  # Print only

def main():
    extractor = Stateless(
        feature_dir = '../../data/DNS/stateless',
        feature_csv = 'stateless.csv'
    )

    extractor.start_sniffing()

if __name__ == "__main__":
    main()
