#!/usr/bin/env python3
# coding:utf8
import argparse
from scapy.all import *
from scapy.layers import http


def sniffer(interface):
    scapy.all.sniff(iface=interface, store=False, prn=callback)


def callback(packet):
    if packet.haslayer(http.HTTPRequest):
	    if packet.haslayer(Raw):
	        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		    # print(str(url) + " : " + str(packet[Raw].load))


parser = argparse.ArgumentParser(description="Outil d'analyse réseau")
parser.add_argument("-iface", dest="iface",
                    help="Interface réseau à utiliser",
                    required=False)
args = parser.parse_args()

if args.iface:
    sniffer(args.iface)
