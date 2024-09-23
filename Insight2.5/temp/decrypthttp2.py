import pyshark
import os
from scapy.utils import RawPcapWriter

key_path = "C:\\Users\\yazee\\ssl1.log"
pcap_file = 'tcpstreamread.pcap'

cap = pyshark.FileCapture(pcap_file,
                          display_filter="http2.streamid eq 5",
                          override_prefs={'ssl.keylog_file': key_path})

# Collect packets into a list
packet_list = [packet for packet in cap]

# Path for saving pcap file
save_directory = './savedpcap'
if not os.path.exists(save_directory):
    os.makedirs(save_directory)

pcapname = "nettrafic"
pcap_file_path = os.path.join(save_directory, f'{pcapname}.pcap')

# Save the pcap file
with RawPcapWriter(pcap_file_path) as writer:
    for packet in packet_list:
        writer.write(packet.raw_data)
