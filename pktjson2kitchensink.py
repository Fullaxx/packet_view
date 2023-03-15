#!/usr/bin/env python3

import os
import sys
import json
import xxhash
from contextlib import suppress

# Extract and Create FTP NDJson Object
def dissectFTP(obj):
	pass

# Extract and Create SSH NDJson Object
def dissectSSH(obj):
	pass

# Extract and Create HTTP NDJson Object
def dissectHTTP(obj):
	pass

# Extract and Create DNS NDJson Object
def dissectDNS(obj):
	pass

# Extract and Create SSDP NDJson Object
def dissectSSDP(obj):
	pass

# Extract and Create MDNS NDJson Object
def dissectMDNS(obj):
	pass

# Extract and Create UDPLite NDJson Object
def dissectUDPLite(obj):
	pass

# Extract and Create SCTP NDJson Object
def dissectSCTP(obj):
	pass

# Extract and Create UDP NDJson Object
def dissectUDP(obj):
	ndjson['udpSrcPort'] = obj['udp.srcport']
	ndjson['udpDstPort'] = obj['udp.dstport']
	ndjson['udpPort'] = [obj['udp.srcport'], obj['udp.dstport']]
	ndjson['udpLenBytes'] = obj['udp.length']
	ndjson['udpChecksum'] = obj['udp.checksum']
	ndjson['udpChecksumStatus'] = obj['udp.checksum.status']
	ndjson['udpStream'] = obj['udp.stream']

# Extract and Create TCP NDJson Object
def dissectTCP(obj):
	tcpflagstree=obj['tcp.flags_tree']
	ndjson['tcpSrcPort'] = obj['tcp.srcport']
	ndjson['tcpDstPort'] = obj['tcp.dstport']
	ndjson['tcpPort'] = [obj['tcp.srcport'], obj['tcp.dstport']]
	ndjson['tcpStream'] = obj['tcp.stream']
	with suppress(KeyError): ndjson['tcpCompleteness'] = obj['tcp.completeness']
	ndjson['tcpLenBytes'] = obj['tcp.len']
	ndjson['tcpSeq'] = obj['tcp.seq']
	ndjson['tcpSeqRaw'] = obj['tcp.seq_raw']
	ndjson['tcpNextSeq'] = obj['tcp.nxtseq']
	ndjson['tcpAck'] = obj['tcp.ack']
	ndjson['tcpAckRaw'] = obj['tcp.ack_raw']
	ndjson['tcpHeaderLenBytes'] = obj['tcp.hdr_len']
	ndjson['tcpFlags'] = obj['tcp.flags']
	ndjson['tcpFlagsReservedBit'] = tcpflagstree['tcp.flags.res']
	ndjson['tcpFlagsNSBit'] = tcpflagstree['tcp.flags.ns']
	ndjson['tcpFlagsCWRBit'] = tcpflagstree['tcp.flags.cwr']
	ndjson['tcpFlagsECNBit'] = tcpflagstree['tcp.flags.ecn']
	ndjson['tcpFlagsURGBit'] = tcpflagstree['tcp.flags.urg']
	ndjson['tcpFlagsACKBit'] = tcpflagstree['tcp.flags.ack']
	ndjson['tcpFlagsPSHBit'] = tcpflagstree['tcp.flags.push']
	ndjson['tcpFlagsRSTBit'] = tcpflagstree['tcp.flags.reset']
	ndjson['tcpFlagsSYNBit'] = tcpflagstree['tcp.flags.syn']
	ndjson['tcpFlagsFINBit'] = tcpflagstree['tcp.flags.fin']

# Extract and Create ICMP NDJson Object
def dissectIGMP(obj):
	pass

# Extract and Create ICMP NDJson Object
def dissectICMP(obj):
	ndjson['icmpType'] = obj['icmp.type']
	ndjson['icmpCode'] = obj['icmp.code']
	ndjson['icmpChecksum'] = obj['icmp.checksum']
	ndjson['icmpChecksumStatus'] = obj['icmp.checksum.status']
	with suppress(KeyError): ndjson['icmpIdent'] = obj['icmp.ident']
	with suppress(KeyError): ndjson['icmpSeq'] = obj['icmp.seq']
	with suppress(KeyError): ndjson['icmpDataTime'] = obj['icmp.data_time']

# Extract and Create IPv6 NDJson Object
def dissectIPv6(obj):
	ndjson['ip6Version'] = obj['ipv6.version']
#	ndjson['ip6TClass'] = ip['ipv6.tclass']
	ndjson['ip6Flow'] = obj['ipv6.flow']
	ndjson['ip6PLen'] = obj['ipv6.plen']
	ndjson['ip6Next'] = obj['ipv6.nxt']
	ndjson['ip6HLim'] = obj['ipv6.hlim']
	ndjson['ip6Src'] = obj['ipv6.src']
	ndjson['ip6Dst'] = obj['ipv6.dst']
	ndjson['ip6Addr'] = [obj['ipv6.src'], obj['ipv6.dst']]

# Extract and Create IPv4 NDJson Object
def dissectIPv4(obj):
	ndjson['ip4Version'] = obj['ip.version']
	ndjson['ip4HeaderLenBytes'] = obj['ip.hdr_len']
#	ndjson[''] = obj['ip.dsfield']
	ndjson['ip4LenBytes'] = obj['ip.len']
	ndjson['ip4ID'] = obj['ip.id']
	ndjson['ip4Flags'] = obj['ip.flags']
	ndjson['ip4FragOffset'] = obj['ip.frag_offset']
	ndjson['ip4TTL'] = obj['ip.ttl']
	ndjson['ip4Proto'] = obj['ip.proto']
	ndjson['ip4Checksum'] = obj['ip.checksum']
	ndjson['ip4ChecksumStatus'] = obj['ip.checksum.status']
	ndjson['ip4Src'] = obj['ip.src']
	ndjson['ip4Dst'] = obj['ip.dst']
	ndjson['ip4Addr'] = [obj['ip.src'], obj['ip.dst']]

# Extract and Create ARP NDJson Object
def dissectARP(obj):
	ndjson['arpHwType'] = obj['arp.hw.type']
	arpType = obj['arp.proto.type']
	arpTypeValue = int(arpType, 16)
	ndjson['arpProtoType'] = '0x'+'{:04x}'.format(arpTypeValue)
	ndjson['arpHwSize'] = obj['arp.hw.size']
	ndjson['arpProtoSize'] = obj['arp.proto.size']
	opcode = obj['arp.opcode']
	ndjson['arpOpCode'] = opcode
	with suppress(KeyError): ndjson['arpSrcHwMac'] = obj['arp.src.hw_mac']
	with suppress(KeyError): ndjson['arpSrcIPv4'] = obj['arp.src.proto_ipv4']
	if(opcode != "1"):
		with suppress(KeyError): ndjson['arpDstHwMac'] = obj['arp.dst.hw_mac']
	with suppress(KeyError): ndjson['arpDstIPv4'] = obj['arp.dst.proto_ipv4']

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
			if  (k ==   'frame'): processFrame(obj)
			elif(k ==     'eth'): dissectEth(obj)
			elif(k ==     'arp'): dissectARP(obj)
			elif(k ==      'ip'): dissectIPv4(obj)
			elif(k ==    'ipv6'): dissectIPv6(obj)
			elif(k ==    'icmp'): dissectICMP(obj)
			elif(k ==    'igmp'): dissectIGMP(obj)
			elif(k ==     'tcp'): dissectTCP(obj)
			elif(k ==     'udp'): dissectUDP(obj)
			elif(k ==    'sctp'): dissectSCTP(obj)
			elif(k == 'udplite'): dissectUDPLite(obj)
			elif(k ==     'ftp'): dissectFTP(obj)
			elif(k ==     'dns'): dissectDNS(obj)
			elif(k ==    'http'): dissectHTTP(obj)
			elif(k ==    'mdns'): dissectMDNS(obj)

		if(os.getenv("JSONARRAY")):
			if(first_line == 0): print('', end=',')
			print(json.dumps(ndjson))
			first_line = 0
		else:
			print('{"index":{"_index":"kitchensink","_type":"_doc"}}')
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
