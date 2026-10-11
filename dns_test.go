package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func wireRecord(name string, kind uint16, data []byte) dnsWireRecord {
	return dnsWireRecord{name: name, recordType: kind, ttl: 300, data: data, message: data, dataEnd: len(data)}
}

func TestNameserverEvidenceAvailability(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ns      []dnsWireRecord
		err     error
		status  string
		warning bool
	}{
		{name: "lookup failure", err: errors.New("timeout"), status: "unavailable"},
		{name: "malformed", ns: []dnsWireRecord{wireRecord("example.com", dnsTypeNS, []byte{0xc0})}, status: "unavailable"},
		{name: "confirmed empty", status: "available", warning: true},
		{name: "one server", ns: []dnsWireRecord{wireRecord("example.com", dnsTypeNS, []byte{2, 'n', 's', 0})}, status: "available", warning: true},
		{name: "two servers", ns: []dnsWireRecord{wireRecord("example.com", dnsTypeNS, []byte{2, 'n', 's', 0}), wireRecord("example.com", dnsTypeNS, []byte{3, 'n', 's', '2', 0})}, status: "available"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := fixtureHostScanner()
			scanner.query = func(_ context.Context, _, _ string, kind uint16) (dnsWireResponse, error) {
				switch kind {
				case dnsTypeSOA:
					return dnsWireResponse{answers: []dnsWireRecord{{name: "example.com", recordType: dnsTypeSOA}}}, nil
				case dnsTypeNS:
					return dnsWireResponse{answers: tc.ns}, tc.err
				default:
					return dnsWireResponse{}, nil
				}
			}
			details := scanner.inspectAdvancedDNS(context.Background(), "example.com", "127.0.0.1:53", nil)
			if details.NameserverStatus != tc.status {
				t.Fatalf("status=%s", details.NameserverStatus)
			}
			r := Result{DNS: details}
			addDNSFindings(&r)
			found := false
			for _, f := range r.Findings {
				if f.Code == "DNS_SINGLE_NAMESERVER" {
					found = true
				}
			}
			if found != tc.warning {
				t.Fatalf("warning=%v, findings=%+v", found, r.Findings)
			}
		})
	}
}

func TestDNSNamesAndCompression(t *testing.T) {
	encoded, err := encodeDNSName("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	name, next, err := readDNSName(encoded, 0)
	if err != nil || name != "www.example.com" || next != len(encoded) {
		t.Fatalf("%s %d %v", name, next, err)
	}
	compressed := append(append([]byte{}, encoded...), 3, 'a', 'p', 'i', 0xc0, 4)
	name, next, err = readDNSName(compressed, len(encoded))
	if err != nil || name != "api.example.com" || next != len(compressed) {
		t.Fatalf("compressed=%s %d %v", name, next, err)
	}
	for _, msg := range [][]byte{{0xc0, 0}, {0xc0}, {0x40, 0}, {3, 'a'}, {0xc0, 255}} {
		if _, _, err := readDNSName(msg, 0); err == nil {
			t.Errorf("accepted malformed %x", msg)
		}
	}
	for _, name := range []string{"a..com", string(make([]byte, 64)) + ".com"} {
		if _, err := encodeDNSName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if got := buildCNAMEChain("a", map[string]string{"a": "b", "b": "a"}); !reflect.DeepEqual(got, []string{"b", "a", "[loop]"}) {
		t.Fatalf("loop=%v", got)
	}
}

func dnsAnswer(query []byte, flags uint16, kind uint16, data []byte) []byte {
	_, end, _ := readDNSName(query, 12)
	response := append([]byte(nil), query[:end+4]...)
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	response = append(response, 0xc0, 12)
	response = binary.BigEndian.AppendUint16(response, kind)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 300)
	response = binary.BigEndian.AppendUint16(response, uint16(len(data)))
	return append(response, data...)
}

func TestDNSResponseAndRecords(t *testing.T) {
	query, id, err := buildDNSQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	response := dnsAnswer(query, 0x81a0, dnsTypeA, []byte{192, 0, 2, 1})
	parsed, err := parseDNSResponse(response, id)
	if err != nil || !parsed.authenticatedData || len(parsed.answers) != 1 || parsed.answers[0].name != "example.com" || parsed.answers[0].ttl != 300 {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	if _, err := parseDNSResponse(response, id+1); err == nil {
		t.Fatal("accepted wrong transaction")
	}
	for n := 0; n < len(response); n++ {
		if _, err := parseDNSResponse(response[:n], id); err == nil {
			t.Fatalf("accepted truncated length %d", n)
		}
	}
	ds, ok := parseDSRecord(wireRecord("example.com", dnsTypeDS, []byte{0, 7, 13, 2, 0xaa}))
	if !ok || ds.KeyTag != 7 || ds.Digest != "AA" {
		t.Fatalf("DS=%+v", ds)
	}
	key, ok := parseDNSKEYRecord(wireRecord("example.com", dnsTypeDNSKEY, []byte{1, 1, 3, 13, 0xaa}))
	if !ok || key.AlgorithmName != "ECDSAP256SHA256" || key.KeyTag == 0 {
		t.Fatalf("DNSKEY=%+v", key)
	}
	caa, ok := parseCAARecord(wireRecord("example.com", dnsTypeCAA, append([]byte{0, 5}, []byte("issueca.example")...)))
	if !ok || caa.Tag != "issue" || caa.Value != "ca.example" {
		t.Fatalf("CAA=%+v", caa)
	}
	https, ok := parseHTTPSRecord(wireRecord("example.com", dnsTypeHTTPS, []byte{0, 1, 0, 0, 3, 0, 2, 1, 187}))
	if !ok || https.Priority != 1 || https.Parameters["port"] != "443" {
		t.Fatalf("HTTPS=%+v", https)
	}
	for _, kind := range []uint16{dnsTypeDS, dnsTypeDNSKEY, dnsTypeCAA, dnsTypeTLSA, dnsTypeHTTPS, dnsTypeRRSIG} {
		r := wireRecord("example.com", kind, nil)
		_, a := parseDSRecord(r)
		_, b := parseDNSKEYRecord(r)
		_, c := parseCAARecord(r)
		_, d := parseTLSARecord(r)
		_, e := parseHTTPSRecord(r)
		_, f := parseRRSIGRecord(r)
		if a || b || c || d || e || f {
			t.Fatalf("accepted empty %d", kind)
		}
	}
}

func TestDNSUDPTruncationFallsBackToTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	udp, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	errs := make(chan error, 2)
	go func() {
		b := make([]byte, 2048)
		n, addr, err := udp.ReadFrom(b)
		if err != nil {
			errs <- err
			return
		}
		response := dnsAnswer(b[:n], 0x8380, dnsTypeA, []byte{192, 0, 2, 1})
		// A TC response can end partway through a record.
		_, err = udp.WriteTo(response[:len(response)-2], addr)
		errs <- err
	}()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		header := make([]byte, 2)
		if _, err = io.ReadFull(conn, header); err != nil {
			errs <- err
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(header))
		if _, err = io.ReadFull(conn, query); err != nil {
			errs <- err
			return
		}
		response := dnsAnswer(query, 0x81a0, dnsTypeA, []byte{192, 0, 2, 1})
		_, err = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(response))), response...))
		errs <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := dnsQuery(ctx, listener.Addr().String(), "example.com", dnsTypeA)
	if err != nil || len(response.answers) != 1 || !response.authenticatedData {
		t.Fatalf("TCP fallback: %+v, %v", response, err)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestDNSExchangeCancellation(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	started := make(chan struct{})
	go func() {
		b := make([]byte, 2048)
		_, _, err := udp.ReadFrom(b)
		if err == nil {
			close(started)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := dnsQuery(ctx, udp.LocalAddr().String(), "example.com", dnsTypeA); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("UDP query not sent")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS ignored cancellation")
	}
}

func FuzzDNSResponse(f *testing.F) {
	query, _, _ := buildDNSQuery("example.com", dnsTypeA)
	binary.BigEndian.PutUint16(query[:2], 0x1234)
	f.Add(dnsAnswer(query, 0x81a0, dnsTypeA, []byte{192, 0, 2, 1}))
	f.Add([]byte{0xc0, 0})
	f.Fuzz(func(t *testing.T, message []byte) {
		if len(message) > 65535 {
			return
		}
		var id uint16
		if len(message) >= 2 {
			id = binary.BigEndian.Uint16(message[:2])
		}
		response, err := parseDNSResponse(message, id)
		if err != nil {
			return
		}
		for _, r := range append(response.answers, response.authority...) {
			parseCAARecord(r)
			parseTLSARecord(r)
			parseHTTPSRecord(r)
			parseDSRecord(r)
			parseDNSKEYRecord(r)
			parseRRSIGRecord(r)
		}
	})
}

func FuzzDNSName(f *testing.F) {
	f.Add([]byte{1, 'a', 0}, 0)
	f.Add([]byte{0xc0, 0}, 0)
	f.Add([]byte{0}, -1)
	f.Fuzz(func(t *testing.T, message []byte, offset int) {
		if len(message) > 65535 {
			return
		}
		name, next, err := readDNSName(message, offset)
		if err == nil && (next < 0 || next > len(message)) {
			t.Fatal(fmt.Sprintf("invalid offset %d for %q", next, name))
		}
	})
}
