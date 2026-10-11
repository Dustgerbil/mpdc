package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func parseDSRecord(record dnsWireRecord) (DSRecord, bool) {
	if record.recordType != dnsTypeDS || len(record.data) < 4 {
		return DSRecord{}, false
	}
	return DSRecord{
		Name:          record.name,
		TTL:           record.ttl,
		KeyTag:        binary.BigEndian.Uint16(record.data[:2]),
		Algorithm:     record.data[2],
		AlgorithmName: dnssecAlgorithmName(record.data[2]),
		DigestType:    record.data[3],
		Digest:        strings.ToUpper(hex.EncodeToString(record.data[4:])),
	}, true
}

func parseDNSKEYRecord(record dnsWireRecord) (DNSKEYRecord, bool) {
	if record.recordType != dnsTypeDNSKEY || len(record.data) < 4 {
		return DNSKEYRecord{}, false
	}
	return DNSKEYRecord{
		Name:          record.name,
		TTL:           record.ttl,
		Flags:         binary.BigEndian.Uint16(record.data[:2]),
		Protocol:      record.data[2],
		Algorithm:     record.data[3],
		AlgorithmName: dnssecAlgorithmName(record.data[3]),
		KeyTag:        dnskeyTag(record.data),
	}, true
}

func parseRRSIGRecord(record dnsWireRecord) (RRSIGRecord, bool) {
	if record.recordType != dnsTypeRRSIG || len(record.data) < 18 {
		return RRSIGRecord{}, false
	}
	signer, _, err := readDNSName(record.message, record.dataOffset+18)
	if err != nil {
		return RRSIGRecord{}, false
	}
	algorithm := record.data[2]
	return RRSIGRecord{
		Name:          record.name,
		TTL:           record.ttl,
		TypeCovered:   dnsTypeName(binary.BigEndian.Uint16(record.data[:2])),
		Algorithm:     algorithm,
		AlgorithmName: dnssecAlgorithmName(algorithm),
		KeyTag:        binary.BigEndian.Uint16(record.data[16:18]),
		SignerName:    normalizeHostname(signer),
		Expiration:    time.Unix(int64(binary.BigEndian.Uint32(record.data[8:12])), 0).UTC(),
		Inception:     time.Unix(int64(binary.BigEndian.Uint32(record.data[12:16])), 0).UTC(),
	}, true
}

func dnskeyTag(data []byte) uint16 {
	var accumulator uint32
	for index, value := range data {
		if index&1 == 0 {
			accumulator += uint32(value) << 8
		} else {
			accumulator += uint32(value)
		}
	}
	accumulator += (accumulator >> 16) & 0xffff
	return uint16(accumulator & 0xffff)
}

func dnssecAlgorithmName(algorithm uint8) string {
	switch algorithm {
	case 5:
		return "RSASHA1"
	case 7:
		return "RSASHA1-NSEC3-SHA1"
	case 8:
		return "RSASHA256"
	case 10:
		return "RSASHA512"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "ED25519"
	case 16:
		return "ED448"
	default:
		return fmt.Sprintf("algorithm-%d", algorithm)
	}
}

func dnsTypeName(recordType uint16) string {
	switch recordType {
	case dnsTypeA:
		return "A"
	case dnsTypeNS:
		return "NS"
	case dnsTypeCNAME:
		return "CNAME"
	case dnsTypeSOA:
		return "SOA"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypeDS:
		return "DS"
	case dnsTypeRRSIG:
		return "RRSIG"
	case dnsTypeDNSKEY:
		return "DNSKEY"
	case dnsTypeTLSA:
		return "TLSA"
	case dnsTypeHTTPS:
		return "HTTPS"
	case dnsTypeCAA:
		return "CAA"
	default:
		return strconv.Itoa(int(recordType))
	}
}

func buildCNAMEChain(host string, links map[string]string) []string {
	current := normalizeHostname(host)
	visited := make(map[string]bool)
	var chain []string
	for {
		target, ok := links[current]
		if !ok {
			return chain
		}
		if visited[current] {
			return append(chain, "[loop]")
		}
		visited[current] = true
		chain = append(chain, target)
		current = target
	}
}

func parseCAARecord(record dnsWireRecord) (CAARecord, bool) {
	if record.recordType != dnsTypeCAA || len(record.data) < 2 {
		return CAARecord{}, false
	}
	tagLength := int(record.data[1])
	if 2+tagLength > len(record.data) || tagLength == 0 {
		return CAARecord{}, false
	}
	return CAARecord{
		Name:  record.name,
		TTL:   record.ttl,
		Flags: record.data[0],
		Tag:   strings.ToLower(string(record.data[2 : 2+tagLength])),
		Value: string(record.data[2+tagLength:]),
	}, true
}

func parseTLSARecord(record dnsWireRecord) (TLSARecord, bool) {
	if record.recordType != dnsTypeTLSA || len(record.data) < 3 {
		return TLSARecord{}, false
	}
	return TLSARecord{
		Name:             record.name,
		TTL:              record.ttl,
		CertificateUsage: record.data[0],
		Selector:         record.data[1],
		MatchingType:     record.data[2],
		AssociationData:  strings.ToUpper(hex.EncodeToString(record.data[3:])),
	}, true
}

func tlsaMatchesEndpoints(record TLSARecord, endpoints []EndpointResult) bool {
	if !usableTLSARecord(record) {
		return false
	}
	association, err := hex.DecodeString(record.AssociationData)
	if err != nil {
		return false
	}
	for _, endpoint := range endpoints {
		var candidates []*x509.Certificate
		if record.CertificateUsage == 1 || record.CertificateUsage == 3 {
			if len(endpoint.peerCertificates) > 0 &&
				tlsaMatchesCertificate(record, association, endpoint.peerCertificates[0]) {
				return true
			}
			continue
		}
		candidates = endpoint.verifiedCertificates
		if len(candidates) == 0 {
			candidates = endpoint.peerCertificates
		}
		for _, cert := range candidates {
			if tlsaMatchesCertificate(record, association, cert) {
				return true
			}
		}
	}
	return false
}

func tlsaMatchesCertificate(record TLSARecord, association []byte, cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	var selected []byte
	switch record.Selector {
	case 0:
		selected = cert.Raw
	case 1:
		selected = cert.RawSubjectPublicKeyInfo
	default:
		return false
	}
	switch record.MatchingType {
	case 0:
		return bytes.Equal(selected, association)
	case 1:
		sum := sha256.Sum256(selected)
		return bytes.Equal(sum[:], association)
	case 2:
		sum := sha512.Sum512(selected)
		return bytes.Equal(sum[:], association)
	default:
		return false
	}
}

func parseHTTPSRecord(record dnsWireRecord) (HTTPSRecord, bool) {
	if record.recordType != dnsTypeHTTPS || len(record.data) < 3 {
		return HTTPSRecord{}, false
	}
	priority := binary.BigEndian.Uint16(record.data[:2])
	target, next, err := readDNSName(record.message, record.dataOffset+2)
	if err != nil || next > record.dataEnd {
		return HTTPSRecord{}, false
	}
	target = normalizeHostname(target)
	parameters := make(map[string]string)
	for next < record.dataEnd {
		if next+4 > record.dataEnd {
			return HTTPSRecord{}, false
		}
		key := binary.BigEndian.Uint16(record.message[next : next+2])
		length := int(binary.BigEndian.Uint16(record.message[next+2 : next+4]))
		next += 4
		if next+length > record.dataEnd {
			return HTTPSRecord{}, false
		}
		value := record.message[next : next+length]
		next += length
		parameters[httpsParameterName(key)] = formatHTTPSParameter(key, value)
	}
	if target == "" {
		target = "."
	}
	return HTTPSRecord{
		Name:       record.name,
		TTL:        record.ttl,
		Priority:   priority,
		TargetName: target,
		Parameters: parameters,
	}, true
}

func httpsParameterName(key uint16) string {
	switch key {
	case 0:
		return "mandatory"
	case 1:
		return "alpn"
	case 2:
		return "no-default-alpn"
	case 3:
		return "port"
	case 4:
		return "ipv4hint"
	case 5:
		return "ech"
	case 6:
		return "ipv6hint"
	default:
		return fmt.Sprintf("key%d", key)
	}
}

func formatHTTPSParameter(key uint16, value []byte) string {
	switch key {
	case 0:
		var names []string
		for len(value) >= 2 {
			names = append(names, httpsParameterName(binary.BigEndian.Uint16(value[:2])))
			value = value[2:]
		}
		return strings.Join(names, ",")
	case 1:
		var protocols []string
		for len(value) > 0 {
			length := int(value[0])
			value = value[1:]
			if length > len(value) {
				return "invalid"
			}
			protocols = append(protocols, string(value[:length]))
			value = value[length:]
		}
		return strings.Join(protocols, ",")
	case 2:
		return "true"
	case 3:
		if len(value) == 2 {
			return strconv.Itoa(int(binary.BigEndian.Uint16(value)))
		}
	case 4:
		var addresses []string
		for len(value) >= net.IPv4len {
			addresses = append(addresses, net.IP(value[:net.IPv4len]).String())
			value = value[net.IPv4len:]
		}
		return strings.Join(addresses, ",")
	case 5:
		encoded := strings.ToUpper(hex.EncodeToString(value))
		if len(encoded) > 64 {
			return encoded[:64] + "..."
		}
		return encoded
	case 6:
		var addresses []string
		for len(value) >= net.IPv6len {
			addresses = append(addresses, net.IP(value[:net.IPv6len]).String())
			value = value[net.IPv6len:]
		}
		return strings.Join(addresses, ",")
	}
	return strings.ToUpper(hex.EncodeToString(value))
}
