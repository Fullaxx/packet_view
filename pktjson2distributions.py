#!/usr/bin/env python3

import os
import sys
import json
import xxhash
from contextlib import suppress

# Extract and Create UDP NDJson Object
def dissectUDP():
	udp=layers['udp']
	ndjson['udpSrcPort'] = udp['udp.srcport']
	ndjson['udpDstPort'] = udp['udp.dstport']
	ndjson['udpPort'] = [udp['udp.srcport'], udp['udp.dstport']]
	ndjson['udpLenBytes'] = udp['udp.length']

# Extract and Create TCP NDJson Object
def dissectTCP():
	tcp=layers['tcp']
	tcpflagstree=tcp['tcp.flags_tree']
	ndjson['tcpSrcPort'] = tcp['tcp.srcport']
	ndjson['tcpDstPort'] = tcp['tcp.dstport']
	ndjson['tcpPort'] = [tcp['tcp.srcport'], tcp['tcp.dstport']]
	ndjson['tcpLenBytes'] = tcp['tcp.len']
	ndjson['tcpFlagsACKBit'] = tcpflagstree['tcp.flags.ack']
	ndjson['tcpFlagsPSHBit'] = tcpflagstree['tcp.flags.push']
	ndjson['tcpFlagsRSTBit'] = tcpflagstree['tcp.flags.reset']
	ndjson['tcpFlagsSYNBit'] = tcpflagstree['tcp.flags.syn']
	ndjson['tcpFlagsFINBit'] = tcpflagstree['tcp.flags.fin']

# Extract and Create IPv6 NDJson Object
def dissectIPv6():
	ip=layers['ipv6']
	ndjson['ip6PLen'] = ip['ipv6.plen']
	ndjson['ip6Next'] = ip['ipv6.nxt']
	ndjson['ip6Src'] = ip['ipv6.src']
	ndjson['ip6Dst'] = ip['ipv6.dst']
	ndjson['ip6Addr'] = [ip['ipv6.src'], ip['ipv6.dst']]
	proto = int(ip['ipv6.nxt'])
	if  (proto ==   6): dissectTCP()
	elif(proto ==  17): dissectUDP()
#	elif(proto == 132): dissectSCTP()
#	elif(proto == 136): dissectUDPLite()

# Extract and Create IPv4 NDJson Object
def dissectIPv4():
	ip=layers['ip']
	ndjson['ip4LenBytes'] = ip['ip.len']
	ndjson['ip4Proto'] = ip['ip.proto']
	ndjson['ip4Src'] = ip['ip.src']
	ndjson['ip4Dst'] = ip['ip.dst']
	ndjson['ip4Addr'] = [ip['ip.src'], ip['ip.dst']]
	proto = int(ip['ip.proto'])
	if  (proto ==   6): dissectTCP()
	elif(proto ==  17): dissectUDP()
#	elif(proto == 132): dissectSCTP()
#	elif(proto == 136): dissectUDPLite()

# Extract and Create Ethernet NDJson Object
def dissectEthernet():
	eth=layers['eth']
	dst_tree=eth['eth.dst_tree']
	src_tree=eth['eth.src_tree']
	ndjson['ethDst'] = eth['eth.dst']
	ndjson['ethSrc'] = eth['eth.src']
	ndjson['ethAddr'] = [eth['eth.dst'], eth['eth.src']]
	with suppress(KeyError): ndjson['ethDstOUI'] = dst_tree['eth.addr.oui_resolved']
	with suppress(KeyError): ndjson['ethSrcOUI'] = src_tree['eth.addr.oui_resolved']
	ethLen = eth.get('eth.len')
	ethType = eth.get('eth.type')
	if(ethLen): ndjson['ethType'] = 'LLC'
	elif(ethType):
		ethTypeValue = int(ethType, 16)
#		WTF why is ethType a long in v3.4.16?? I should not have to do this
		ndjson['ethType'] = '0x'+'{:04x}'.format(ethTypeValue)
		if ethTypeValue == 0x0800: dissectIPv4()
		if ethTypeValue == 0x86dd: dissectIPv6()

def processPackets(packets):
	global ndjson
	global layers
	global first_line
	for packet in packets:
		source=packet['_source']
		layers=source['layers']
		frame=layers['frame']

#		Create a unique packetID
		x = xxhash.xxh128()
		x.update(json.dumps(packet))
		packetID = x.hexdigest()
		x.reset()

		ndjson = {}
		ndjson['packetID'] = packetID
		ndjson['captureTime'] = frame['frame.time_epoch']
		ndjson['frameCapLen'] = frame['frame.cap_len']
#		ndjson['frameProtocols'] = frame['frame.protocols']
		ndjson['frameProtocols'] = frame['frame.protocols'].split(':')
		if int(frame['frame.encap_type']) == 1: dissectEthernet()

		if(os.getenv("JSONARRAY")):
			if(first_line == 0): print('', end=',')
			print(json.dumps(ndjson))
			first_line = 0
		else:
			print('{"index":{"_index":"metadata","_type":"_doc"}}')
			print(json.dumps(ndjson))

if __name__ == "__main__":
	global first_line
	if(os.getenv("JSONARRAY")): print('[')
	first_line = 1
	argc = len(sys.argv)
	if(argc > 1):
		for i in range(1, argc):
			f = open(sys.argv[i], "r")
			packets=json.loads(f.read())
			processPackets(packets)
	else:
		packets=json.loads(sys.stdin.read())
		processPackets(packets)

	if(os.getenv("JSONARRAY")): print(']')
