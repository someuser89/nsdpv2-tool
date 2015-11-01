#!/usr/bin/python
import socket
import binascii

SPORT = 64513
DPORT = 64515
timeout = 5

def parsDiscover(msg):
	assert msg != None
	"pars an discover package"
	m = binascii.hexlify(msg).decode()
	ret = {}
	# magicnummber
	assert m[:2] == "00"
	assert m[2:4] == "02"
	# netgear IP
	assert m[32:40] == "0c07d2f2"
	# pars src mac (switch)
	mac = m[8:20]
	out = []
	while mac:
		out.append(mac[:2])
		mac = mac[2:]
	ret["mac"] =  ":".join(out)
	# return
	return ret

def parsFirmware(msg):
	assert msg != None
	"pars an discover package"
	m = binascii.hexlify(msg).decode()
	ret = {}
	# magicnummber
	assert m[:2] == "00"
	assert m[2:4] == "02"
	assert m[4:8] == "0001"
	# netgear IP
	assert m[32:40] == "0c07d2f2"
	# pars src mac (switch)
	mac = m[8:20]
	out = []
	while mac:
		out.append(mac[:2])
		mac = mac[2:]
	ret["mac"] =  ":".join(out)
	# return
	return ret

def buildPkgDiscover():
	data = "\x00\x02\x00\x00"
	data += "\x00"*6
	data += "\x00\x00\x00\x01\x00\x00"
	data += "\x0c\x07\xd2\xf2"
	data += "\x00"*6 # dest_mac
	data += "\x00\x00" + "\x00"*12
	return data

def getSendSocket(SRC_IP):
	ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	try:
		ssocket.bind((SRC_IP, SPORT))
	except socket.error as error:
		print "Error: " + SRC_IP + " not found any network interface"
		exit(1)
	return ssocket

def getReceiveSocket():
	rsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	rsocket.settimeout(timeout)
	rsocket.bind(("255.255.255.255", SPORT))
	return rsocket

def readFromSocket(rsocket):
	try:
		message, address = rsocket.recvfrom(4096)
	except socket.timeout:
		return (None, None)
	except rsocket.error as error:
		if error.errno == errno.EAGAIN:
			return (None, None)
		raise
	return (message, address)

def TLV(nr, value):
	def TLV_length(payload_length):
		return "\x00" + chr(4 + payload_length)
	def TLV_id(nr):
		if type(nr) == int and nr in (1, 2, 3, 4, 5, 6, 7, 8, 9):
			return "\x00" + chr(nr)
		elif type(nr) == str:
			return "\x00" + chr(int(nr, 16))
		assert False
	data = TLV_id(nr) + TLV_length(len(value)) + value
	return data

def buildPkgFirmware(DST_MAC, password):
	def convertMac(mac):
		data = ""
		for c in mac:
			if c != ":":
				data += c
		return data.decode("hex")
	data = "\x00\x02\x00\x00"
	data += convertMac(DST_MAC)
	data += "\x00\x03\x00\x0a\x00\x00"
	data += "\x0c\x07\xd2\xf2"
	data += "\x00"*6 # dest_mac
	data += "\x00\x02" + "\x00"*12
	data += TLV("9", password)
	return data
