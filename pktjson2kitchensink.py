#!/usr/bin/env python3

import os
import sys
import json
import xxhash
from contextlib import suppress

def dissectFTP():
	pass

def dissectSSH():
	pass

def dissectHTTP():
	pass

def dissectDNS():
	dns=layers['dns']
	dnsflagstree=dns['dns.flags_tree']
	ndjson['dnsID'] = dns['dns.id']
	ndjson['dnsFlags'] = dns['dns.flags']
	ndjson['dnsResponseBit'] = dnsflagstree['dns.flags.response']
	ndjson['dnsOpcodeBit'] = dnsflagstree['dns.flags.opcode']
#	ndjson['dnsTruncatedBit'] = dnsflagstree['dns.flags.truncated']
#	ndjson['dnsRecDesiredBit'] = dnsflagstree['dns.flags.recdesired']
#	ndjson['dnsZBit'] = dnsflagstree['dns.flags.z']
#	ndjson['dnsCheckDisableBit'] = dnsflagstree['dns.flags.checkdisable']

def dissectSSDP():
	pass

def dissectMDNS():
	pass


# Extract and Create UDPLite NDJson Object
def dissectUDPLite():
	pass
#	udplite=layers['udplite']
#	ndjson['udpLiteSrcPort'] = udplite['udp.srcport']
#	ndjson['udpLiteDstPort'] = udplite['udp.dstport']
#	ndjson['udpLitePort'] = [udplite['udp.srcport'], udp['udp.dstport']]
#	ndjson['udpLiteLenBytes'] = udplite['udp.length']
#	ndjson['udpChecksum'] = udp['udp.checksum']
#	ndjson['udpChecksumStatus'] = udp['udp.checksum.status']
#	ndjson['udpStream'] = udp['udp.stream']

# Extract and Create SCTP NDJson Object
def dissectSCTP():
	pass

# Extract and Create UDP NDJson Object
def dissectUDP():
	udp=layers['udp']
	ndjson['udpSrcPort'] = udp['udp.srcport']
	ndjson['udpDstPort'] = udp['udp.dstport']
	ndjson['udpPort'] = [udp['udp.srcport'], udp['udp.dstport']]
	ndjson['udpLenBytes'] = udp['udp.length']
	ndjson['udpChecksum'] = udp['udp.checksum']
	ndjson['udpChecksumStatus'] = udp['udp.checksum.status']
	ndjson['udpStream'] = udp['udp.stream']

# Extract and Create TCP NDJson Object
def dissectTCP():
	tcp=layers['tcp']
	tcpflagstree=tcp['tcp.flags_tree']
	ndjson['tcpSrcPort'] = tcp['tcp.srcport']
	ndjson['tcpDstPort'] = tcp['tcp.dstport']
	ndjson['tcpPort'] = [tcp['tcp.srcport'], tcp['tcp.dstport']]
	ndjson['tcpStream'] = tcp['tcp.stream']
	with suppress(KeyError): ndjson['tcpCompleteness'] = tcp['tcp.completeness']
	ndjson['tcpLenBytes'] = tcp['tcp.len']
	ndjson['tcpSeq'] = tcp['tcp.seq']
	ndjson['tcpSeqRaw'] = tcp['tcp.seq_raw']
	ndjson['tcpNextSeq'] = tcp['tcp.nxtseq']
	ndjson['tcpAck'] = tcp['tcp.ack']
	ndjson['tcpAckRaw'] = tcp['tcp.ack_raw']
	ndjson['tcpHeaderLenBytes'] = tcp['tcp.hdr_len']
	ndjson['tcpFlags'] = tcp['tcp.flags']
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
def dissectIGMP():
	igmp=layers['igmp']

# Extract and Create ICMP NDJson Object
def dissectICMP():
	icmp=layers['icmp']
	ndjson['icmpType'] = icmp['icmp.type']
	ndjson['icmpCode'] = icmp['icmp.code']
	ndjson['icmpChecksum'] = icmp['icmp.checksum']
	ndjson['icmpChecksumStatus'] = icmp['icmp.checksum.status']
	with suppress(KeyError): ndjson['icmpIdent'] = icmp['icmp.ident']
	with suppress(KeyError): ndjson['icmpSeq'] = icmp['icmp.seq']
	with suppress(KeyError): ndjson['icmpDataTime'] = icmp['icmp.data_time']

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
	proto = int(ip['ipv6.nxt'])
	if  (proto ==   1): dissectICMP()
	elif(proto ==   2): dissectIGMP()
	elif(proto ==   6): dissectTCP()
	elif(proto ==  17): dissectUDP()
	elif(proto == 132): dissectSCTP()
	elif(proto == 136): dissectUDPLite()

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
	proto = int(ip['ip.proto'])
	if  (proto ==   1): dissectICMP()
	elif(proto ==   2): dissectIGMP()
	elif(proto ==   6): dissectTCP()
	elif(proto ==  17): dissectUDP()
	elif(proto == 132): dissectSCTP()
	elif(proto == 136): dissectUDPLite()

def dissectARP():
	pass

def dissectLLC():
	ndjson['ethType'] = 'LLC'

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
		if  (ethTypeValue == 0x0800): dissectIPv4()
		elif(ethTypeValue == 0x0806): dissectARP()
		elif(ethTypeValue == 0x86dd): dissectIPv6()

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

#		Handle Protocols above Transport Layer
		if 'ftp' in ndjson['frameProtocols']: dissectFTP()
		if 'ssh' in ndjson['frameProtocols']: dissectSSH()
		if 'http' in ndjson['frameProtocols']: dissectHTTP()
		if 'dns' in ndjson['frameProtocols']: dissectDNS()
		if 'ssdp' in ndjson['frameProtocols']: dissectSSDP()
		if 'mdns' in ndjson['frameProtocols']: dissectMDNS()

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
