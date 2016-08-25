from scapy.all import *
def http_302_inject(pkt):
		string = "HTTP/1.1 302 Moved Permanently\r\n"
		string += "Location: www.facebook.com\r\n"
		string += "\r\n"
		inject_packet = pkt.copy()
		inject_packet.show()
def http_monitor(pkt):
	if pkt.haslayer(Raw):
		raw_data = str(pkt[Raw].load)
		if 'GET' in raw_data:
			pkt.show()
			http_302_inject(pkt)

my_ip = '192.168.1.19'
sniff(prn=http_monitor, filter='host 192.168.1.19 and tcp port 80',store=0)
