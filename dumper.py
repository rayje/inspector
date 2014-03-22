#!/usr/bin/env python

import dpkt

def read_pcap(filename, on_packet=None, num_packets=None):
	packets = 0
	with open(filename) as f:
		pcap = dpkt.pcap.Reader(f)
		for ts, buf in pcap:
			eth = dpkt.ethernet.Ethernet(buf)
			on_packet(ts, eth)
			packets += 1
			if num_packets and packets > num_packets:
				return

def print_packet(ts, eth):
	print "="*80
	print `ts`
	print `eth`
	print "-"*80

if __name__ == "__main__":
	filename = 'test.pcap'

	read_pcap(filename, print_packet, 5)