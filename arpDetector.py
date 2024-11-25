from scapy.all import sniff, ARP, Ether
from collections import defaultdict

class ARPSpoofingDetector:
    def __init__(self):
        self.ip_mac_map = defaultdict(set)
    
    def process_packet(self, packet):
        if packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[Ether].src
            
            # Check if this MAC address has been associated with different IPs
            if src_mac in self.ip_mac_map and src_ip not in self.ip_mac_map[src_mac]:
                print(f"Potential ARP Spoofing Detected!")
                print(f"MAC Address {src_mac} previously associated with IPs: {self.ip_mac_map[src_mac]}")
                print(f"Now claiming IP: {src_ip}")
            
            # Add or update the mapping
            self.ip_mac_map[src_mac].add(src_ip)
    
    def start_sniffing(self):
        print("Starting ARP Spoofing Detection...")
        sniff(filter="arp", prn=self.process_packet, store=0)

# Usage
detector = ARPSpoofingDetector()
detector.start_sniffing()
