from scapy.all import *

my_ip='10.211.55.7'
gateway='10.211.55.1'

def arp_monitor_callback(pkt):
	if pkt[IP].src==my_ip:
		if pkt.haslayer(TCP) and pkt.haslayer(Raw):
			if pkt[TCP].dport == 80:
				pkt[TCP].show()
				print pkt[Raw].load
				pay = pkt[Raw].load
				pay = pay.split('\n')[0]
				pay = pay.split(' ')[0]
				if pay =='GET':
					pkt[Raw].load = pkt[Raw].load + "bloacked"
				pkt[TCP].show()
				print pkt[TCP].flags
				print "gooo"
				send(pkt)		
					
while True: sniff(prn=arp_monitor_callback, filter="host "+ my_ip + " and host " + gateway, count=1)
