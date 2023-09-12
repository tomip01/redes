from scapy.all import *

count = 0

def contador(pkt):
    global count
    count += 1
    if count % 10 == 0:
        print(count)

sniffedPackets = sniff(count=10000, prn = contador)
wrpcap("PacketsTomas-pocoUso.pcap", sniffedPackets)

