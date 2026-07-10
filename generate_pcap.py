from scapy.all import Ether, IP, TCP, wrpcap

# Create a small PCAP file with synthetic packets
packets = [
    Ether()/IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="S"),
    Ether()/IP(src="10.0.0.1", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA"),
    Ether()/IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="A"),
    # Anomalous looking packet
    Ether()/IP(src="172.16.0.5", dst="10.0.0.1")/TCP(sport=22, dport=443, flags="FPU")
]

wrpcap("test.pcap", packets)
print("test.pcap generated successfully.")
