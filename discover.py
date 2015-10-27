from optparse import OptionParser
from func import *

parser = OptionParser()
parser.add_option("-s", "--src", help="source ip address", type="str" )

(options, args) = parser.parse_args()

if not options.src:
	print "use --help"
	exit(1)

# get send socket
ssocket = getSendSocket(options.src)
# get receive socket
rsocket = getReceiveSocket()
# send discover
ssocket.sendto(buildPkgDiscover(), ("255.255.255.255", DPORT))
#
message, address = readFromSocket(rsocket)
if message == None and address == None:
	print "no switches found"
else:
	data = parsDiscover(message)
	print "Found:"
	print address[0], data["mac"]
