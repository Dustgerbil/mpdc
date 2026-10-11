package main

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	dnsTypeA      = 1
	dnsTypeNS     = 2
	dnsTypeCNAME  = 5
	dnsTypeSOA    = 6
	dnsTypeAAAA   = 28
	dnsTypeDS     = 43
	dnsTypeRRSIG  = 46
	dnsTypeDNSKEY = 48
	dnsTypeTLSA   = 52
	dnsTypeHTTPS  = 65
	dnsTypeCAA    = 257
)

type dnsWireRecord struct {
	name       string
	recordType uint16
	ttl        uint32
	data       []byte
	dataOffset int
	dataEnd    int
	message    []byte
}

type dnsWireResponse struct {
	authenticatedData bool
	truncated         bool
	responseCode      int
	answers           []dnsWireRecord
	authority         []dnsWireRecord
}

func dnsResolverAddress(configured string) (string, error) {
	if configured != "" {
		return ensureDNSPort(configured), nil
	}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("cannot determine DNS resolver: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			return ensureDNSPort(fields[1]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("cannot read DNS resolver configuration: %w", err)
	}
	return "", errors.New("no nameserver found in /etc/resolv.conf; use --dns-server")
}

func ensureDNSPort(address string) string {
	address = strings.TrimSpace(address)
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	if parsed := net.ParseIP(address); parsed != nil {
		return net.JoinHostPort(address, "53")
	}
	if strings.Count(address, ":") > 1 {
		return net.JoinHostPort(address, "53")
	}
	return net.JoinHostPort(address, "53")
}

func dnsQuery(ctx context.Context, resolver, name string, recordType uint16) (dnsWireResponse, error) {
	var empty dnsWireResponse
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	query, id, err := buildDNSQuery(name, recordType)
	if err != nil {
		return empty, err
	}

	responseBytes, err := exchangeDNSUDP(ctx, resolver, query)
	if err != nil {
		return empty, err
	}
	response, err := parseDNSResponse(responseBytes, id)
	if err != nil {
		return empty, err
	}
	if response.truncated {
		responseBytes, err = exchangeDNSTCP(ctx, resolver, query)
		if err != nil {
			return empty, err
		}
		response, err = parseDNSResponse(responseBytes, id)
		if err != nil {
			return empty, err
		}
	}
	if response.truncated {
		return empty, errors.New("DNS TCP response was truncated")
	}
	switch response.responseCode {
	case 0, 3:
		return response, nil
	case 2:
		return response, errors.New("resolver returned SERVFAIL (possible DNSSEC failure or transient resolver error)")
	default:
		return response, fmt.Errorf("resolver returned DNS response code %d", response.responseCode)
	}
}

func buildDNSQuery(name string, recordType uint16) ([]byte, uint16, error) {
	name = normalizeHostname(name)
	var random [2]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(random[:])
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100) // Recursion desired.
	binary.BigEndian.PutUint16(message[4:6], 1)
	binary.BigEndian.PutUint16(message[10:12], 1) // One OPT pseudo-record.

	encodedName, err := encodeDNSName(name)
	if err != nil {
		return nil, 0, err
	}
	message = append(message, encodedName...)
	message = binary.BigEndian.AppendUint16(message, recordType)
	message = binary.BigEndian.AppendUint16(message, 1)

	// EDNS(0), 1232-byte UDP payload, with the DNSSEC OK bit set.
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, 41)
	message = binary.BigEndian.AppendUint16(message, 1232)
	message = binary.BigEndian.AppendUint32(message, 0x00008000)
	message = binary.BigEndian.AppendUint16(message, 0)
	return message, id, nil
}

func encodeDNSName(name string) ([]byte, error) {
	if name == "" {
		return []byte{0}, nil
	}
	var encoded []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		if len(encoded)+len(label)+2 > 255 {
			return nil, fmt.Errorf("DNS name is too long: %q", name)
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0), nil
}

func exchangeDNSUDP(ctx context.Context, resolver string, query []byte) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: connectionTimeout}).DialContext(ctx, "udp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(connectionTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func exchangeDNSTCP(ctx context.Context, resolver string, query []byte) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: connectionTimeout}).DialContext(ctx, "tcp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(connectionTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	lengthBytes := make([]byte, 2)
	if _, err := ioReadFull(conn, lengthBytes); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes))
	response := make([]byte, length)
	if _, err := ioReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func ioReadFull(reader net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := reader.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, errors.New("unexpected end of DNS TCP response")
		}
	}
	return total, nil
}

func parseDNSResponse(message []byte, expectedID uint16) (dnsWireResponse, error) {
	var response dnsWireResponse
	if len(message) < 12 {
		return response, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(message[0:2]) != expectedID {
		return response, errors.New("DNS response ID does not match query")
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 {
		return response, errors.New("DNS packet is not a response")
	}
	response.truncated = flags&0x0200 != 0
	response.authenticatedData = flags&0x0020 != 0
	response.responseCode = int(flags & 0x000f)
	// TC may truncate a record itself; retry over TCP before decoding sections.
	if response.truncated {
		return response, nil
	}
	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	answerCount := int(binary.BigEndian.Uint16(message[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(message[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(message[10:12]))

	offset := 12
	for i := 0; i < questionCount; i++ {
		_, next, err := readDNSName(message, offset)
		if err != nil {
			return response, err
		}
		offset = next
		if offset+4 > len(message) {
			return response, errors.New("truncated DNS question")
		}
		offset += 4
	}

	totalRecords := answerCount + authorityCount + additionalCount
	for i := 0; i < totalRecords; i++ {
		record, next, err := readDNSRecord(message, offset)
		if err != nil {
			return response, err
		}
		offset = next
		if i < answerCount {
			response.answers = append(response.answers, record)
		} else if i < answerCount+authorityCount {
			response.authority = append(response.authority, record)
		}
	}
	return response, nil
}

func readDNSRecord(message []byte, offset int) (dnsWireRecord, int, error) {
	var record dnsWireRecord
	name, next, err := readDNSName(message, offset)
	if err != nil {
		return record, offset, err
	}
	if next+10 > len(message) {
		return record, offset, errors.New("truncated DNS resource record")
	}
	recordType := binary.BigEndian.Uint16(message[next : next+2])
	ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
	length := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
	dataOffset := next + 10
	dataEnd := dataOffset + length
	if dataEnd > len(message) {
		return record, offset, errors.New("truncated DNS resource data")
	}
	record = dnsWireRecord{
		name:       normalizeHostname(name),
		recordType: recordType,
		ttl:        ttl,
		data:       message[dataOffset:dataEnd],
		dataOffset: dataOffset,
		dataEnd:    dataEnd,
		message:    message,
	}
	return record, dataEnd, nil
}

func readDNSName(message []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(message) {
		return "", offset, errors.New("DNS name offset is outside the message")
	}
	var labels []string
	next := -1
	position := offset
	visited := make(map[int]bool)
	for steps := 0; steps < 128; steps++ {
		if position < 0 || position >= len(message) {
			return "", offset, errors.New("truncated DNS name")
		}
		if visited[position] {
			return "", offset, errors.New("DNS compression pointer loop")
		}
		visited[position] = true
		length := int(message[position])
		switch {
		case length == 0:
			if next < 0 {
				next = position + 1
			}
			return strings.Join(labels, "."), next, nil
		case length&0xc0 == 0xc0:
			if position+1 >= len(message) {
				return "", offset, errors.New("truncated DNS compression pointer")
			}
			if next < 0 {
				next = position + 2
			}
			position = int(binary.BigEndian.Uint16(message[position:position+2]) & 0x3fff)
		case length&0xc0 != 0:
			return "", offset, errors.New("invalid DNS label encoding")
		default:
			position++
			if position+length > len(message) {
				return "", offset, errors.New("truncated DNS label")
			}
			labels = append(labels, string(message[position:position+length]))
			position += length
		}
	}
	return "", offset, errors.New("DNS name exceeds compression traversal limit")
}
