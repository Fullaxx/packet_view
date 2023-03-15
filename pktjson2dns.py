#!/usr/bin/env python3

import os
import sys
import json
import xxhash
from contextlib import suppress

def dissectDNS(obj):
	if obj.get('_ws.malformed'): return
	ndjson['dnsID'] = obj['dns.id']
	dnsQueryCount = int(obj['dns.count.queries'])
#	There should only be one question
#	If there are multiple questions this code will open a wormhole to the beginning of time ...
#	or just ignore all questions except one (the last one?)
	if (dnsQueryCount > 0):
		ndjson['dnsQueryCount'] = dnsQueryCount
		queries = obj['Queries']
		for k,d in queries.items():
			qryname = d.get('dns.qry.name')
			ndjson['dnsQueryName'] = qryname

	dnsAnswerCount = int(obj['dns.count.answers'])
	if (dnsAnswerCount > 0):
		ndjson['dnsAnswerCount'] = dnsAnswerCount
		answers = obj['Answers']
		resplist = []
		for k,d in answers.items(): resplist.append(k)
		ndjson['dnsResponses'] = resplist

#		This would walk all the answer blocks and pull elements
#		for k,d in answers.items():
#			ans = None
#			respname = d.get('dns.resp.name')
#			resptype = d.get('dns.resp.type')
#			if   (resptype ==  '1'): ans = d.get('dns.a')
#			elif (resptype ==  '5'): ans = d.get('dns.cname')
#			elif (resptype == '28'): ans = d.get('dns.aaaa')
#			print('respname: ' + respname + ': ' + resptype)
#			if(ans is not None): print('ANSWER: ' + ans)

# Extract and Create UDP NDJson Object
def dissectUDP(obj):
	ndjson['udpSrcPort'] = obj['udp.srcport']
	ndjson['udpDstPort'] = obj['udp.dstport']
	ndjson['udpPort'] = [obj['udp.srcport'], obj['udp.dstport']]
	ndjson['udpLenBytes'] = obj['udp.length']

# Extract and Create IPv6 NDJson Object
def dissectIPv6(obj):
	ndjson['ip6PLen'] = obj['ipv6.plen']
	ndjson['ip6Next'] = obj['ipv6.nxt']
	ndjson['ip6Src'] = obj['ipv6.src']
	ndjson['ip6Dst'] = obj['ipv6.dst']
	ndjson['ip6Addr'] = [obj['ipv6.src'], obj['ipv6.dst']]

# Extract and Create IPv4 NDJson Object
def dissectIPv4(obj):
	ndjson['ip4LenBytes'] = obj['ip.len']
	ndjson['ip4Proto'] = obj['ip.proto']
	ndjson['ip4Src'] = obj['ip.src']
	ndjson['ip4Dst'] = obj['ip.dst']
	ndjson['ip4Addr'] = [obj['ip.src'], obj['ip.dst']]

# Extract and Create Ethernet NDJson Object
def dissectEth(obj):
	dst_tree=obj['eth.dst_tree']
	src_tree=obj['eth.src_tree']
	ndjson['ethDst'] = obj['eth.dst']
	ndjson['ethSrc'] = obj['eth.src']
	ndjson['ethAddr'] = [obj['eth.dst'], obj['eth.src']]
	with suppress(KeyError): ndjson['ethDstOUI'] = dst_tree['eth.addr.oui_resolved']
	with suppress(KeyError): ndjson['ethSrcOUI'] = src_tree['eth.addr.oui_resolved']
	ethLen = obj.get('eth.len')
	ethType = obj.get('eth.type')
	if(ethLen): ndjson['ethType'] = 'LLC'
	elif(ethType):
		ethTypeValue = int(ethType, 16)
#		WTF why is ethType a long in v3.4.16?? I should not have to do this
		ndjson['ethType'] = '0x'+'{:04x}'.format(ethTypeValue)

# Extract and Create Frame NDJson Object
def processFrame(obj):
	ndjson['captureTime'] = obj['frame.time_epoch']
	ndjson['frameCapLen'] = obj['frame.cap_len']
	ndjson['frameProtocols'] = obj['frame.protocols'].split(':')

def processPackets(packets):
	global ndjson
	global first_line
	for packet in packets:
		source=packet['_source']
		layers=source['layers']

#		Create a unique packetID
		x = xxhash.xxh128()
		x.update(json.dumps(packet))
		packetID = x.hexdigest()
		x.reset()

		ndjson = {}
		ndjson['packetID'] = packetID
		for k,obj in layers.items():
			if  (k == 'frame'): processFrame(obj)
			elif(k ==   'eth'): dissectEth(obj)
			elif(k ==    'ip'): dissectIPv4(obj)
			elif(k ==  'ipv6'): dissectIPv6(obj)
			elif(k ==   'udp'): dissectUDP(obj)
			elif(k ==   'dns'): dissectDNS(obj)

		if(os.getenv("JSONARRAY")):
			if(first_line == 0): print('', end=',')
			print(json.dumps(ndjson))
			first_line = 0
		else:
			print('{"index":{"_index":"dns","_type":"_doc"}}')
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
