#!/usr/bin/env python3

import re
import csv
import math
import os.path

from scapy.all import *
from collections import Counter

def extract_query_name(packet):
    """Extract query name from packet"""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode('utf-8') if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname
        return qname.rstrip('.')
    return None

def calculate_entropy(domain_string):
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

def extract_character_features(domain_string):
    """Extract character count features"""
    features = {
        'upper': sum(1 for c in domain_string if c.isupper()),
        'lower': sum(1 for c in domain_string if c.islower()),
        'numeric': sum(1 for c in domain_string if c.isdigit()),
        'special': sum(1 for c in domain_string if c in '-_=\t'),
        'FQDN_count': len(domain_string)
    }

    return features

def extract_label_features(domain_string):
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

def extract_longest_word(domain_string):
    """Extract longest meaningful word feature"""
    # Remove dots and special characters
    cleaned = re.sub(r'[^a-zA-Z]', ' ', domain_string)
    words = cleaned.split()

    if not words or len(domain_string) == 0:
        return 0.0

    longest = max(words, key=len) if words else ''
    # Longest word over domain length average
    return len(longest) / len(domain_string) if len(domain_string) > 0 else 0.0

def get_stateless_features(packet):
    query_name = extract_query_name(packet)

    if not query_name:
        return None

    features = {}

    # Character-based features
    char_features = extract_character_features(query_name)
    features.update(char_features)

    # Entropy
    features['entropy'] = calculate_entropy(query_name)

    # Label-based features
    label_features = extract_label_features(query_name)
    features.update(label_features)

    # Longest word feature
    features['longest_word'] = extract_longest_word(query_name)

    # Write feature rows to csv file
    filename = 'sample.csv'
    with open(filename, 'a', newline='') as csvfile:
        fieldnames = ['upper', 'lower', 'numeric', 'special', 'FQDN_count', 'entropy', 'labels', 'labels_max', 'labels_average', 'sld', 'subdomain', 'subdomain_length', 'len', 'longest_word']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not os.path.isfile(filename):
            writer.writeheader()
        writer.writerows([features])

    return features

# Sniff packages
sniff(filter="udp port 53", prn=get_stateless_features, store=False)
