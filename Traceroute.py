
# Adapted from companion material available for the textbook Computer Networking: A Top-Down Approach, 6th Edition
# Kurose & Ross Â©2013

import socket
import os
import sys
import struct
import time
import select
import binascii
import random
import string
import codecs
ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT  = 2.0
TRIES    = 2

def checksum(string):
	csum = 0
	countTo = (len(string) // 2) * 2

	count = 0
	while count < countTo:
		thisVal = ord(string[count+1]) * 256 + ord(string[count])
		csum = csum + thisVal
		csum = csum & 0xffffffff
		count = count + 2

	if countTo < len(string):
		csum = csum + ord(string[len(string) - 1])
		csum = csum & 0xffffffff

	csum = (csum >> 16) + (csum & 0xffff)
	csum = csum + (csum >> 16)
	answer = ~csum
	answer = answer & 0xffff
	answer = answer >> 8 | (answer << 8 & 0xff00)
	return answer

def build_packet(data_size):
	# First, make the header of the packet, then append the checksum to the header,
	# then finally append the data

	# dont send the packet yet, just return the final packet in this function.
	# So the function ending should look like this
	# Note: padding = bytes(data_size)
	########################################
	ICMP_ECHO = 8
	code = 0
	packetId = 1#random.randrange(0,200)
	seqNum = 9#random.randrange(0,200)
	checkSum = 1
	#header = str(ICMP_ECHO)+str(code)+str(checkSum)+str(p_id)+str(seqNum)
	#print(header)
	#print(p_id, '   ',seqNum,'\n')
	#   cited   https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python
	header = struct.pack("!BBHHh", ICMP_ECHO, 0, checkSum,packetId, seqNum)
	#print(ICMP_ECHO, 0, checkSum,packetId, seqNum,'     expected values')
	#hexH= binascii.hexlify(header).hex()
	#print(hexH,"hexh")
	#print((binascii.hexlify(header),),'binasci hexlify')
	#de =header.decode('latin-1')
	#de += 'hi'
	#print((de),de.encode('latin-1'), header.decode('latin-1'),"decode")
	#h_str = binascii.hexlify(header)
	#print("".join("{:02X}".format(ord(x)) for x in header),"format ord")
	#  cited https://pythontips.com/2013/07/28/generating-a-random-string/
	#https://stackoverflow.com/questions/10880813/typeerror-sequence-item-0-expected-string-int-found
	values = ''.join(chr(v) for v in header)
	#print(values, '   values')
	data = ''.join([random.choice(string.ascii_letters) for n in range(data_size)])
	#print(data)
	#data = data.encode("latin-1").hex()
	#print(data,"    hexed data")
	padding =str(data_size)
	#padding = binascii.b2a_hex(data_size)

	packet = values + data #+ padding
	print("pack = ",packet)
	#packet_S = packet.decode('hex')
	#print(packet,"     strpck")
	rtnCS = checksum(packet)
	print(rtnCS)
	#  https: // stackoverflow.com / questions / 55218931 / calculating - checksum -for -icmp - echo - request - in -python
	#  https: // piazza.com /class /k892xt0vqjs3x5?cid=254 ---htons()
	data = data.encode()
	header1 = struct.pack("!BBHHH", ICMP_ECHO, 0, socket.htons(rtnCS), packetId, seqNum)
	packet1 = header1 #+ data  +bytes(data_size)
	#print(packet1)
	return packet1

def get_route(hostname,data_size):
	timeLeft = TIMEOUT
	for ttl in range(1,MAX_HOPS):
		for tries in range(TRIES):

			destAddr = socket.gethostbyname(hostname)

			# SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
			#Fill in start
			# Make a raw socket named mySocket
			mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
			#cited https: // www.programcreek.com / python / example / 7887 / socket.SOCK_RAW
			#Fill in end

			# setsockopt method is used to set the time-to-live field.
			mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
			mySocket.settimeout(TIMEOUT)
			try:
				d = build_packet(data_size)
				mySocket.sendto(d, (hostname, 0))
				t= time.time()
				startedSelect = time.time()
				whatReady = select.select([mySocket], [], [], timeLeft)
				howLongInSelect = (time.time() - startedSelect)
				if whatReady[0] == []: # Timeout
					print("  *        *        *    Request timed out.")
				recvPacket, addr = mySocket.recvfrom(1024)
				timeReceived = time.time()
				timeLeft = timeLeft - howLongInSelect
				if timeLeft <= 0:
					print("  *        *        *    Request timed out.")

			except socket.timeout:
				continue

			else:
				#Fill in start
				#Fetch the icmp type from the IP packet
				# https://piazza.com/class/k892xt0vqjs3x5?cid=264----- 20-28 gets the icmp header information
				icmpHeaderInfo = recvPacket[20:28]
				types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeaderInfo)
				#Fill in end

				if types == 11:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived -t)*1000, addr[0]))

				elif types == 3:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived-t)*1000, addr[0]))

				elif types == 0:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived - t)*1000, addr[0]))
					return

				else:
					print("error")
				break
			finally:
				mySocket.close()


print('Argument List: {0}'.format(str(sys.argv)))

data_size = 0
if len(sys.argv) >= 2:
	data_size = int(sys.argv[1])
#data_size=0
print(data_size)
#get_route("oregonstate.edu",data_size)
get_route("www.google.com", data_size)
#build_packet(data_size)
#get_route("gaia.cs.umass.edu",data_size)