from scapy import *
def http_302_inject(pkt):
		inject_packet = pkt.copy()
		inject_packet.show()
def http_monitor(pkt):
	if pkt.haslayer(Raw):
		raw_data = str(pkt[Raw].load)
		if 'GET' in raw_data:
			pkt.show()
			http_302_inject(pkt)

my_ip = '10.211.55.13'
sniff(prn=http_monitor, filter='host 10.211.55.13 and tcp port 80',store=0)
