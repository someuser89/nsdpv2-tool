import socket
import binascii

SPORT = 64513
DPORT = 64515
timeout = 2

DST_MAC = "e0:91:f5:97:51:6c"
SRC_IP = "192.168.0.22"

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

def buildPkgFirmware():
	def convertMac(mac):
		data = ""
		for c in mac:
			if c != ":":
				data += c
		return data.decode("hex")
	password = "password"
	data = "\x00\x02\x00\x00"
	data += convertMac(DST_MAC)
	data += "\x00\x03\x00\x0a\x00\x00"
	data += "\x0c\x07\xd2\xf2"
	data += "\x00"*6 # dest_mac
	data += "\x00\x02" + "\x00"*12
	data += TLV("9", password)
	return data

def buildPkgDiscover():
	data = "\x00\x02\x00\x00"
	data += "\x00"*6
	data += "\x00\x00\x00\x01\x00\x00"
	data += "\x0c\x07\xd2\xf2"
	data += "\x00"*6 # dest_mac
	data += "\x00\x00" + "\x00"*12
	return data

# send socket
ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
ssocket.bind((SRC_IP, SPORT))

# receive socket
rsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
rsocket.settimeout(timeout)
rsocket.bind(("255.255.255.255", SPORT))

# send discover
ssocket.sendto(buildPkgDiscover(), ("255.255.255.255", DPORT))

def read(rsocket):
	try:
		message, address = rsocket.recvfrom(4096)
	except rsocket.timeout:
		return (None, None)
	except rsocket.error as error:
		if error.errno == errno.EAGAIN:
			return (None, None)
		raise
	message_hex = binascii.hexlify(message).decode()
	print("recv=" + message_hex)
	return (message, address)

read(rsocket)
