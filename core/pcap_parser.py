import logging
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import os

logger = logging.getLogger('flask.app')

def parse_pcap(filepath):
    """
    Parses a PCAP file and extracts network features for each packet.
    
    Args:
        filepath (str): Path to the .pcap file.
        
    Returns:
        list: A list of dictionaries, where each dictionary contains features
              extracted from a single packet.
    """
    if not os.path.exists(filepath):
        logger.error(f"PCAP file not found: {filepath}")
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    try:
        logger.info(f"Starting to parse PCAP file: {filepath}")
        packets = rdpcap(filepath)
    except Exception as e:
        logger.error(f"Failed to read PCAP file {filepath}: {e}")
        raise ValueError(f"Failed to read PCAP file. Ensure it is a valid .pcap format. Details: {e}")

    extracted_data = []

    for pkt_num, packet in enumerate(packets, start=1):
        try:
            # Initialize default values
            pkt_info = {
                "packet_id": pkt_num,
                "src_ip": None,
                "dst_ip": None,
                "protocol": 0,
                "src_port": 0,
                "dst_port": 0,
                "packet_size": len(packet),
                "tcp_flags": 0
            }

            # Extract IP layer information
            if IP in packet:
                pkt_info["src_ip"] = packet[IP].src
                pkt_info["dst_ip"] = packet[IP].dst
                pkt_info["protocol"] = packet[IP].proto

            # Extract Transport layer information (TCP)
            if TCP in packet:
                pkt_info["src_port"] = packet[TCP].sport
                pkt_info["dst_port"] = packet[TCP].dport
                pkt_info["tcp_flags"] = int(packet[TCP].flags)
            # Extract Transport layer information (UDP)
            elif UDP in packet:
                pkt_info["src_port"] = packet[UDP].sport
                pkt_info["dst_port"] = packet[UDP].dport

            # We only append packets that have IP layer for our analysis
            if pkt_info["src_ip"] is not None:
                extracted_data.append(pkt_info)

        except Exception as e:
            logger.warning(f"Error parsing packet #{pkt_num}: {e}")
            continue

    logger.info(f"Successfully parsed {len(extracted_data)} valid IP packets from {filepath}")
    return extracted_data
