#!/usr/bin/env python

import dpkt, socket

flags = [30,10,24,16]
fnames = ["AckPsh","Ack","AckRst","PshRstSyn"]

class Packet(object):

	def __init__(self, ts, eth):
		self.ts = ts
		self.data = eth
		self.ip = eth.data
		self.tcp = self.ip.data

	def __repr__(self):
		return 'Packet(ts='+str(self.ts)+',data='+repr(self.data)+')'

def read_pcap(filename, packet_filter=None):
	packets = []
	with open(filename) as f:
		pcap = dpkt.pcap.Reader(f)
		for ts, buf in pcap:
			pkt = Packet(ts, dpkt.ethernet.Ethernet(buf))

			# If a filter is provided call on_packet only
			# if filter return True
			if packet_filter and packet_filter(pkt):
				packets.append(pkt)
			elif not packet_filter:		
				packets.append(pkt)
	return packets

			

def packet_filter(addrs, ports=None):
	def filter_func(pkt):
		eth = pkt.data
		ip = eth.data
		tcp = ip.data
		ip_src, ip_dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
		ip_addrs = [ip_src, ip_dst]
		tcp_ports = [tcp.sport, tcp.dport]

		match = len(set(ip_addrs).intersection(addrs)) == 2
		if ports:
			match = match and len(set(tcp_ports).intersection(ports)) == 2
		return match
	return filter_func


def print_packets(pkts):
	first = pkts[0]
	tcp = first.data.data.data
	seq = tcp.seq
	ack = tcp.ack

	map(print_packet(seq,ack), pkts)

def print_packet(seq,ack):
	print seq, ack
	def print_packet(pkt):
		eth = pkt.data
		ip = eth.data
		tcp = ip.data
		ip_src = socket.inet_ntoa(ip.src)
		ip_dst = socket.inet_ntoa(ip.dst)

		print "="*80
		print 'ts:', pkt.ts
		print 'seq:', tcp.seq, 'ack:', tcp.ack
		print 'seq:', get_value(seq,ack,tcp.seq), 'ack:', get_value(seq,ack,tcp.ack)
		print `tcp`
		print "{0:b}".format(tcp.flags), tcp.flags
		# print fnames[flags.index(tcp.flags)]
		print 'IP:', ip_src+':'+str(tcp.sport), '>', ip_dst+':'+str(tcp.dport)
	return print_packet

def get_value(seq, ack, val):
	s1 = val-seq
	a1 = val-ack

	if s1 < 0:
		return a1
	elif a1 < 0:
		return s1
	elif a1 < s1:
		return a1
	return s1


if __name__ == "__main__":
	# http://media.packetlife.net/media/blog/attachments/424/TCP_example.cap
	filename = 'TCP_example.cap'
	# filename = 'test.pcap'

	# addrs = ['192.168.1.2', '174.143.213.184']
	# ports = [54841,80]

	# map(print_packet, 
	# 		read_pcap(filename,
	# 			packet_filter=packet_filter(addrs, ports)))
	# packets = read_pcap(filename, packet_filter=pf)

	print_packets(read_pcap(filename))#, packet_filter(addrs,ports)))