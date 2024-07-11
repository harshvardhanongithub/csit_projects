from scapy.all import sniff, IP, TCP, UDP, ICMP
import re

# Define a list of simple rules
rules = [
    {"id": 1, "description": "Detect TCP traffic to port 80 (HTTP)", "pattern": lambda pkt: pkt.haslayer(TCP) and pkt[TCP].dport == 80},
    {"id": 2, "description": "Detect UDP traffic to port 53 (DNS)", "pattern": lambda pkt: pkt.haslayer(UDP) and pkt[UDP].dport == 53},
    {"id": 3, "description": "Detect ICMP traffic", "pattern": lambda pkt: pkt.haslayer(ICMP)},
    {"id": 4, "description": "Detect suspicious payload", "pattern": lambda pkt: pkt.haslayer(TCP) and b"malicious" in bytes(pkt[TCP].payload)}
]

def alert(rule, pkt):
    print(f"Alert! Rule ID: {rule['id']} - {rule['description']}")
    print(f"Packet: {pkt.summary()}")
    pkt.show()

def packet_handler(pkt):
    for rule in rules:
        if rule["pattern"](pkt):
            alert(rule, pkt)

def start_sniffing(interface):
    print(f"Starting IDS on interface {interface}")
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == "__main__":
    interface = "Wi-Fi"  # Replace with your actual network interface name
    start_sniffing(interface)
