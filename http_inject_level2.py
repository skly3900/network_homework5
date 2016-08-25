from scapy.all import *

def backward_in(packet):
		reverse_packet =packet.copy()
		string = 'Blocked\r\n'
		string += '\r\n'
		print '************************************'
		reverse_packet.show()
		print '************************************'
		seq_plus=len(packet[Raw].load)
		print seq_plus
		print '-------------------'	
		reverse_packet[Ether].src = packet[Ether].dst
		reverse_packet[Ether].dst = packet[Ether].src
		reverse_packet[IP].src = packet[IP].dst
		reverse_packet[IP].dst = packet[IP].src
		reverse_packet[IP].len = 40 + len(string)
		reverse_packet[TCP].sport = packet[TCP].dport
		reverse_packet[TCP].dport = packet[TCP].sport
		reverse_packet[TCP].seq = packet[TCP].ack
		reverse_packet[TCP].ack = packet[TCP].seq + seq_plus
		reverse_packet[TCP].flags = 'PA'
		reverse_packet[Raw].load = string 
		reverse_packet.show()
		sendp(reverse_packet)


def http_monitor(pkt):
	if pkt.haslayer(Raw):
		raw_data = str(pkt[Raw].load)
		if 'GET' in raw_data:
			pkt.show()
			backward_in(pkt)

my_ip = '192.168.1.19'
sniff(prn=http_monitor, filter='host 192.168.1.19 and tcp port 80',store=0)
