#!/usr/bin/python

from scapy.all import *
def forward_in(pkt):
	packet = pkt.copy()
	packet[TCP].flags ='F'
	packet[Raw].load ='Blocekd\r\n\r\n'
	print'-------------'
	packet.show()
	sendp(packet)
def http_monitor(pkt):
	if pkt.haslayer(Raw):
		raw_data= str(pkt[Raw].load)
		if 'GET' in raw_data:
			pkt.show()
			forward_in(pkt)	


my_ip= '10.211.55.13'

sniff(prn=http_monitor, filter ='host 10.211.55.13 and tcp port 80', store =0)

