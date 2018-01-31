#!/usr/bin/env python3

import socket, sys
from struct import *

# create an INET, STREAMing socket
skt = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# receive packets
#while True:
counter = 0
while counter < 1000:
	packet = skt.recvfrom(65565)

	# packet string from tuple
	packet = packet[0]
	
	#take first 20 characters for the IP header
	ip_header = packet[0:20]

	#now unpack them - for the 1st parm, i found this useful: https://stackoverflow.com/questions/20768107/regarding-struct-unpack-in-python
	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	
	#internet header version
	version_ihl = iph[0]
	# >> is a bitwise operator, it 'moves' all bits to the right (by 4 below)
	version = version_ihl >> 4	
	ihl = version_ihl & 0xF
	
	iph_length = ihl * 4

	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8])
	d_addr = socket.inet_ntoa(iph[9])


	# now we print internet header version, IP header length, TTL, protocol, and our source + dest addresses
	#moved this down to the if statement to remove SSH noise
	#print('Version: ' + str(version) + '| IP Header Length: ' + str(iph_length) + '| TTL : ' + str(ttl) + '| Protocol: ' + str(protocol) + '| Source: ' + str(s_addr) + '| Destination: ' + str(d_addr))


	#now TCP header - ':' is the delimiter of the slice syntax used to 'slice out' sub-parts in sequences, [start:end]
	tcp_header = packet[iph_length:iph_length+20]
	
	#now unpack
	tcph = unpack('!HHLLBBHHH' , tcp_header)
	
	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4


	#moved down below like other line for ip header
	#print('Source Port : ' + str(source_port) + '| Dest Port : ' + str(dest_port) + '| Sequence Number : ' + str(sequence) + '| Acknowledgement : ' + str(acknowledgement) + '| TCP header length : ' + str(tcph_length))


	h_size = iph_length + tcph_length * 4
	data_size = len(packet) - h_size

	#get data from the packet
	data = packet[h_size:] # basically everything after the headers


        #little if statement to get rid of noise i was seeing while doing this all remotely (ssh)
	if dest_port != 22:
		print('Version: ' + str(version) + '| IP Header Length: ' + str(iph_length) + '| TTL : ' + str(ttl) + '| Protocol: ' + str(protocol) + '| Source: ' + str(s_addr) + '| Destination: ' + str(d_addr))
		print('Source Port : ' + str(source_port) + '| Dest Port : ' + str(dest_port) + '| Sequence Number : ' + str(sequence) + '| Acknowledgement : ' + str(acknowledgement) + '| TCP header length : ' + str(tcph_length))
		print('Data: ' + str(data))
	else:
		pass

	#print('Data: ' + str(data))
	
	counter = counter + 1

	
# brainfarts down here
"""
	try:
		if type(data) == bytes:
			data = data.decode("utf-8")
		print(data)
	except:
		pass


counter = 0
while counter < 100:
	pkt = skt.recvfrom(2084)
	print(pkt)
	counter = counter + 1
"""
