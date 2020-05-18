

# Adapted from companion material available for the textbook Computer Networking: A Top-Down Approach, 6th Edition
# Kurose & Ross Â©2013
#David Passaro
#passarod@oregonstate.edu
#372-400 SPRING
#Project 3 Traceroute

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
		thisVal = (string[count+1]) * 256 + (string[count])
		csum = csum + thisVal
		csum = csum & 0xffffffff
		count = count + 2

	if countTo < len(string):
		csum = csum + (string[len(string) - 1])
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
	icmp_echo_num = 8
	code = 0
	packetId = 1  #given randomly here
	seqNum = 1
	checkSum = 1
	#   cited   https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python
	#  cited https://pythontips.com/2013/07/28/generating-a-random-string/
	#https://stackoverflow.com/questions/10880813/typeerror-sequence-item-0-expected-string-int-found

	#https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python
	chars = []
	begin = 0x41
	size = 10
	for i in range(begin, begin + (data_size)):  # here we fill the chars into the list for the package
		chars += [(i & 0xff)]
	data = bytes(chars)  # turn to bytes for the checksum
	header = struct.pack("!bbHHh", icmp_echo_num, 0, checkSum,packetId, 1) #struct pack for getting the bytes in specific order
	checkSum = checksum(header + data) #check the sum
	#  https: // stackoverflow.com / questions / 55218931 / calculating - checksum -for -icmp - echo - request - in -python
	#  https: // piazza.com /class /k892xt0vqjs3x5?cid=254 ---htons()

	checkSum = socket.htons(checkSum) + 1 # had to inc as I saw it was off by one in wireshark
	header = struct.pack("!bbHHh", icmp_echo_num, 0, checkSum, packetId, 1) # repack with the new checksum

	packet = header + data
	return packet

def get_route(hostname,data_size):
	timeLeft = TIMEOUT
	for ttl in range(1,MAX_HOPS):
		for tries in range(TRIES):

			destAddr = socket.gethostbyname(hostname)

			# SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
			#Fill in start
			# Make a raw socket named mySocket
			mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
			# set up socket  with the protocol
			#cited https: // www.programcreek.com / python / example / 7887 / socket.SOCK_RAW --ex 4
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
				# https://piazza.com/class/k892xt0vqjs3x5?cid=264----- 20-28 gets the icmp header information (starts at
				# 160B
				icmpHeaderInfo = recvPacket[20:28]
				types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeaderInfo)  # unload into the
				# variables in proper order
				# Fill in end

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
					print('types = ', types)
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
else:
	data_size = 10

print("OSU")
get_route("www.oregonstate.edu",data_size)
print("CHINA")
get_route('www.china.org.cn', data_size)
print("GOOGLE")
get_route("www.google.com", data_size)
print("SWEDEN")
get_route('www.sweden.se', data_size)

#get_route("gaia.cs.umass.edu",data_size)