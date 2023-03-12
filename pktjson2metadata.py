#!/usr/bin/env python3

import os
import sys
import json
import xxhash
from contextlib import suppress

# Extract and Create IPv6 NDJson Object
def dissectIPv6():
	ip=layers['ipv6']
	ndjson['ip6Version'] = ip['ipv6.version']
#	ndjson['ip6TClass'] = ip['ipv6.tclass']
	ndjson['ip6Flow'] = ip['ipv6.flow']
	ndjson['ip6PLen'] = ip['ipv6.plen']
	ndjson['ip6Next'] = ip['ipv6.nxt']
	ndjson['ip6HLim'] = ip['ipv6.hlim']
	ndjson['ip6Src'] = ip['ipv6.src']
	ndjson['ip6Dst'] = ip['ipv6.dst']
	ndjson['ip6Addr'] = [ip['ipv6.src'], ip['ipv6.dst']]

# Extract and Create IPv4 NDJson Object
def dissectIPv4():
	ip=layers['ip']
	ndjson['ip4Version'] = ip['ip.version']
	ndjson['ip4HeaderLenBytes'] = ip['ip.hdr_len']
#	ndjson[''] = ip['ip.dsfield']
	ndjson['ip4LenBytes'] = ip['ip.len']
	ndjson['ip4ID'] = ip['ip.id']
	ndjson['ip4Flags'] = ip['ip.flags']
	ndjson['ip4FragOffset'] = ip['ip.frag_offset']
	ndjson['ip4TTL'] = ip['ip.ttl']
	ndjson['ip4Proto'] = ip['ip.proto']
	ndjson['ip4Checksum'] = ip['ip.checksum']
	ndjson['ip4ChecksumStatus'] = ip['ip.checksum.status']
	ndjson['ip4Src'] = ip['ip.src']
	ndjson['ip4Dst'] = ip['ip.dst']
	ndjson['ip4Addr'] = [ip['ip.src'], ip['ip.dst']]

def dissectARP():
	pass

def dissectLLC():
	pass

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
	if(ethLen): dissectLLC()
	elif(ethType):
		ethTypeValue = int(ethType, 16)
#		WTF why is ethType a long in v3.4.16?? I should not have to do this
		ndjson['ethType'] = '0x'+'{:04x}'.format(ethTypeValue)
		if ethTypeValue == 0x0800: dissectIPv4()
		if ethTypeValue == 0x0806: dissectARP()
		if ethTypeValue == 0x0866: dissectIPv6()

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
		ndjson['frameProtocols'] = frame['frame.protocols']
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
