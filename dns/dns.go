package dns

import (
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// IsDNSPacket checks if the given packet is a DNS query/response (UDP or TCP to/from port 53).
// Assumes packet is an IP packet (IPv4 or IPv6). Returns true if it's DNS, false otherwise.
func IsDNSPacket(packet []byte) bool {
	if len(packet) < 20 { // Min IPv4 header
		return false
	}
	ipVersion := packet[0] >> 4
	if ipVersion == 4 {
		ihl := int(packet[0]&0xF) * 4 // IPv4 header length
		if len(packet) < ihl || ihl < 20 {
			return false
		}
		proto := packet[9] // Protocol (UDP=17, TCP=6)
		if proto != 17 && proto != 6 {
			return false
		}
		dstPortOffset := ihl + 2 // DST port in UDP/TCP header
		if len(packet) < dstPortOffset+2 {
			return false
		}
		dstPort := binary.BigEndian.Uint16(packet[dstPortOffset : dstPortOffset+2])
		return dstPort == 53
	} else if ipVersion == 6 {
		if len(packet) < 40 { // Min IPv6 header
			return false
		}
		proto := packet[6] // Next header
		headerLen := 40
		// Skip extension headers (simplified: loop until non-extension)
		for proto == 0 || proto == 43 || proto == 44 || proto == 50 || proto == 51 || proto == 60 { // Common extensions
			if len(packet) < headerLen+8 {
				return false
			}
			proto = packet[headerLen]
			extLen := int(packet[headerLen+1])*8 + 8
			headerLen += extLen
		}
		if proto != 17 && proto != 6 {
			return false
		}
		dstPortOffset := headerLen + 2
		if len(packet) < dstPortOffset+2 {
			return false
		}
		dstPort := binary.BigEndian.Uint16(packet[dstPortOffset : dstPortOffset+2])
		return dstPort == 53
	}
	return false
}

// IsBlockedDomain checks if the DNS packet contains a query for a blocked domain.
// Returns true if blocked, false otherwise, and an error if parsing fails.
func IsBlockedDomain(packet []byte, blockedDomains []string) (bool, error) {
	// Extract DNS payload (skip IP and transport headers)
	ipVersion := packet[0] >> 4
	var payload []byte
	var headerLen int
	var isTCP bool
	if ipVersion == 4 {
		headerLen = int(packet[0]&0xF) * 4
		if len(packet) < headerLen {
			return false, errors.New("invalid IPv4 header")
		}
		proto := packet[9]
		isTCP = proto == 6
		payload = packet[headerLen:]
	} else if ipVersion == 6 {
		headerLen = 40
		if len(packet) < headerLen {
			return false, errors.New("invalid IPv6 header")
		}
		proto := packet[6]
		isTCP = proto == 6
		payload = packet[headerLen:]
	} else {
		return false, errors.New("unsupported IP version")
	}

	var dnsPayload []byte
	if isTCP {
		if len(payload) < 20 {
			return false, errors.New("invalid TCP header")
		}
		tcpHeaderLen := int(payload[12]>>4) * 4
		if len(payload) < tcpHeaderLen {
			return false, errors.New("invalid TCP header length")
		}
		dnsOffset := tcpHeaderLen
		if len(payload) < dnsOffset+2 {
			return false, errors.New("invalid TCP DNS length prefix")
		}
		dnsLen := int(binary.BigEndian.Uint16(payload[dnsOffset : dnsOffset+2]))
		dnsOffset += 2
		if len(payload) < dnsOffset+dnsLen {
			return false, errors.New("invalid TCP DNS payload")
		}
		dnsPayload = payload[dnsOffset : dnsOffset+dnsLen]
	} else { // UDP
		if len(payload) < 8 {
			return false, errors.New("invalid UDP header")
		}
		udpLen := int(binary.BigEndian.Uint16(payload[4:6]))
		if udpLen < 8 || len(payload) < udpLen {
			return false, errors.New("invalid UDP length")
		}
		dnsPayload = payload[8:udpLen]
	}

	// Parse DNS query
	var parser dnsmessage.Parser
	header, err := parser.Start(dnsPayload)
	if err != nil {
		return false, err
	}
	if header.Response {
		return false, nil // Ignore responses
	}

	questions, err := parser.AllQuestions()
	if err != nil {
		return false, err
	}

	for _, q := range questions {
		domain := q.Name.String()
		if domain != "" && domain[len(domain)-1] == '.' {
			domain = domain[:len(domain)-1] // Remove trailing dot
		}
		for _, blocked := range blockedDomains {
			if strings.HasSuffix(domain, blocked) {
				return true, nil
			}
		}
	}

	return false, nil
}
