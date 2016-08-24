from scapy.all import *

def backward_in(pkt):
		packet =pkt.copy()

def http_monitor:
	if pkt.haslayer(Raw):
		raw_data = str(pkt[Raw].load)
		if 'GET' int raw_data:
			pkt.show()
			backward_in(pkt)
my_ip = '10.211.55.13'
sniff(prn=http_monitor, filter='host 10.211.55.13 and tcp port 80',store=0)
