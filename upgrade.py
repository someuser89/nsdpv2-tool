from optparse import OptionParser
from func import *

parser = OptionParser()
parser.add_option("-s", "--src", help="source ip address", type="str" )
parser.add_option("-m", "--mac", help="destination mac address (switch)", type="str" )
parser.add_option("-p", "--password", help="switch password", type="str" )

(options, args) = parser.parse_args()

if not options.src or not options.mac or not options.password:
	print "use --help"
	exit(1)

# get send socket
ssocket = getSendSocket(options.src)
# get receive socket
rsocket = getReceiveSocket()
# enable firmware upgrade mode
ssocket.sendto(buildPkgFirmware(options.mac, options.password), ("255.255.255.255", DPORT))
#
message, address = readFromSocket(rsocket)
data = parsFirmware(message)
assert data['mac'] == options.mac
print "Switch response!"
print "run tftp jet"
