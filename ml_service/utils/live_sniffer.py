import threading
import time
import random
import sys

# We keep a rolling window of network stats
class NetworkStats:
    def __init__(self):
        self.reset()
        self.is_sniffing = False
        self.error = None

    def reset(self):
        self.packets = 0
        self.bytes = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.unique_ports = set()
        self.packet_sizes = []

stats = NetworkStats()

def packet_callback(packet):
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        if not IP in packet:
            return
            
        stats.packets += 1
        pkt_len = len(packet)
        stats.bytes += pkt_len
        stats.packet_sizes.append(pkt_len)
        
        if TCP in packet:
            stats.tcp_packets += 1
            if hasattr(packet[TCP], 'dport'):
                stats.unique_ports.add(packet[TCP].dport)
        elif UDP in packet:
            stats.udp_packets += 1
            if hasattr(packet[UDP], 'dport'):
                stats.unique_ports.add(packet[UDP].dport)
        elif ICMP in packet:
            stats.icmp_packets += 1
    except Exception:
        pass

def sniff_loop():
    try:
        from scapy.all import sniff
        stats.is_sniffing = True
        sniff(prn=packet_callback, store=False)
    except Exception as e:
        stats.is_sniffing = False
        stats.error = str(e)

def start_sniffer():
    t = threading.Thread(target=sniff_loop, daemon=True)
    t.start()

def get_live_features():
    if not stats.is_sniffing:
        # Fallback to normal behavior if scapy isn't working
        return {
            'packets_per_second': random.randint(30, 80),
            'bytes_per_second': random.randint(40000, 100000),
            'tcp_ratio': random.uniform(0.5, 0.7),
            'udp_ratio': random.uniform(0.2, 0.4),
            'icmp_ratio': random.uniform(0.01, 0.05),
            'unique_ports': random.randint(2, 6),
            'avg_packet_size': random.randint(800, 1400),
            'status': 'simulated_fallback',
            'error': stats.error
        }
    
    # Calculate features over the last second (approx)
    total_packets = max(1, stats.packets)
    features = {
        'packets_per_second': stats.packets,
        'bytes_per_second': stats.bytes,
        'tcp_ratio': stats.tcp_packets / total_packets,
        'udp_ratio': stats.udp_packets / total_packets,
        'icmp_ratio': stats.icmp_packets / total_packets,
        'unique_ports': len(stats.unique_ports),
        'avg_packet_size': sum(stats.packet_sizes) / total_packets if stats.packet_sizes else 0,
        'status': 'live'
    }
    
    stats.reset()
    return features
