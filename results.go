package main

import (
	"crypto/x509"
	"time"
)

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type CertificateInfo struct {
	Subject                string    `json:"subject"`
	Issuer                 string    `json:"issuer"`
	AltNames               []string  `json:"alt_names,omitempty"`
	WildcardAltNames       []string  `json:"wildcard_alt_names,omitempty"`
	Issued                 time.Time `json:"issued"`
	Expiry                 time.Time `json:"expiry"`
	DaysRemaining          int       `json:"days_remaining"`
	TimeStatus             string    `json:"time_status"`
	SerialNumber           string    `json:"serial_number"`
	FingerprintSHA256      string    `json:"fingerprint_sha256"`
	PublicKeyAlgorithm     string    `json:"public_key_algorithm"`
	PublicKeyBits          int       `json:"public_key_bits,omitempty"`
	PublicKeyCurve         string    `json:"public_key_curve,omitempty"`
	SignatureAlgorithm     string    `json:"signature_algorithm"`
	KeyUsage               []string  `json:"key_usage,omitempty"`
	ExtendedKeyUsage       []string  `json:"extended_key_usage,omitempty"`
	IsCA                   bool      `json:"is_ca"`
	OCSPServers            []string  `json:"ocsp_servers,omitempty"`
	CRLDistributionPoints  []string  `json:"crl_distribution_points,omitempty"`
	IssuingCertificateURLs []string  `json:"issuing_certificate_urls,omitempty"`
	TLSFeatures            []int     `json:"tls_features,omitempty"`
	MustStaple             bool      `json:"must_staple"`
}

type EndpointResult struct {
	Incomplete            bool                `json:"incomplete,omitempty"`
	TLSAStatus            string              `json:"tlsa_status,omitempty"`
	IP                    string              `json:"ip"`
	AddressFamily         string              `json:"address_family"`
	IPClassification      string              `json:"ip_classification"`
	TCPReachable          bool                `json:"tcp_reachable"`
	TLSHandshake          bool                `json:"tls_handshake"`
	CertificateValid      bool                `json:"certificate_valid"`
	ChainTrusted          bool                `json:"chain_trusted"`
	HostnameMatch         bool                `json:"hostname_match"`
	TLSVersion            string              `json:"tls_version,omitempty"`
	CipherSuite           string              `json:"cipher_suite,omitempty"`
	KeyExchange           string              `json:"key_exchange,omitempty"`
	ALPN                  string              `json:"alpn,omitempty"`
	ServerName            string              `json:"server_name,omitempty"`
	SupportedTLSVersions  []string            `json:"supported_tls_versions,omitempty"`
	SupportedCipherSuites map[string][]string `json:"supported_cipher_suites,omitempty"`
	Certificate           *CertificateInfo    `json:"certificate,omitempty"`
	PeerChain             []CertificateInfo   `json:"peer_chain,omitempty"`
	VerifiedChain         []CertificateInfo   `json:"verified_chain,omitempty"`
	OCSPStapled           bool                `json:"ocsp_stapled"`
	OCSPResponseBytes     int                 `json:"ocsp_response_bytes,omitempty"`
	SCTCount              int                 `json:"sct_count"`
	VerificationError     string              `json:"verification_error,omitempty"`
	Error                 string              `json:"error,omitempty"`
	Findings              []Finding           `json:"findings,omitempty"`
	peerCertificates      []*x509.Certificate
	verifiedCertificates  []*x509.Certificate
}

type MailSecurity struct {
	MX           []string `json:"mx,omitempty"`
	SPF          []string `json:"spf,omitempty"`
	DMARC        []string `json:"dmarc,omitempty"`
	MTASTSRecord []string `json:"mta_sts_record,omitempty"`
	TLSReporting []string `json:"tls_reporting,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

type DNSRecordTTL struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type CAARecord struct {
	Name            string `json:"name"`
	TTL             uint32 `json:"ttl"`
	Flags           uint8  `json:"flags"`
	Tag             string `json:"tag"`
	Value           string `json:"value"`
	DNSSECValidated bool   `json:"dnssec_validated"`
}

type TLSARecord struct {
	Name                  string `json:"name"`
	TTL                   uint32 `json:"ttl"`
	CertificateUsage      uint8  `json:"certificate_usage"`
	Selector              uint8  `json:"selector"`
	MatchingType          uint8  `json:"matching_type"`
	AssociationData       string `json:"association_data"`
	MatchesPresentedChain bool   `json:"matches_presented_chain"`
	DNSSECValidated       bool   `json:"dnssec_validated"`
}

type HTTPSRecord struct {
	Name            string            `json:"name"`
	TTL             uint32            `json:"ttl"`
	Priority        uint16            `json:"priority"`
	TargetName      string            `json:"target_name"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	DNSSECValidated bool              `json:"dnssec_validated"`
}

type NameserverRecord struct {
	Name      string   `json:"name"`
	TTL       uint32   `json:"ttl"`
	Addresses []string `json:"addresses,omitempty"`
}

type DSRecord struct {
	Name          string `json:"name"`
	TTL           uint32 `json:"ttl"`
	KeyTag        uint16 `json:"key_tag"`
	Algorithm     uint8  `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	DigestType    uint8  `json:"digest_type"`
	Digest        string `json:"digest"`
}

type DNSKEYRecord struct {
	Name          string `json:"name"`
	TTL           uint32 `json:"ttl"`
	Flags         uint16 `json:"flags"`
	Protocol      uint8  `json:"protocol"`
	Algorithm     uint8  `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	KeyTag        uint16 `json:"key_tag"`
}

type RRSIGRecord struct {
	Name          string    `json:"name"`
	TTL           uint32    `json:"ttl"`
	TypeCovered   string    `json:"type_covered"`
	Algorithm     uint8     `json:"algorithm"`
	AlgorithmName string    `json:"algorithm_name"`
	KeyTag        uint16    `json:"key_tag"`
	SignerName    string    `json:"signer_name"`
	Inception     time.Time `json:"inception"`
	Expiration    time.Time `json:"expiration"`
}

type DNSDetails struct {
	NameserverStatus  string             `json:"nameserver_status,omitempty"`
	Resolver          string             `json:"resolver,omitempty"`
	DNSSECStatus      string             `json:"dnssec_status"`
	AuthenticatedData bool               `json:"authenticated_data"`
	Zone              string             `json:"zone,omitempty"`
	CNAMEChain        []string           `json:"cname_chain,omitempty"`
	RecordTTLs        []DNSRecordTTL     `json:"record_ttls,omitempty"`
	Nameservers       []NameserverRecord `json:"nameservers,omitempty"`
	CAA               []CAARecord        `json:"caa,omitempty"`
	TLSA              []TLSARecord       `json:"tlsa,omitempty"`
	HTTPS             []HTTPSRecord      `json:"https_records,omitempty"`
	DS                []DSRecord         `json:"ds,omitempty"`
	DNSKEY            []DNSKEYRecord     `json:"dnskey,omitempty"`
	RRSIG             []RRSIGRecord      `json:"rrsig,omitempty"`
	Errors            []string           `json:"errors,omitempty"`
}

type Result struct {
	Incomplete    bool `json:"incomplete,omitempty"`
	SchemaVersion int  `json:"schema_version"`

	// Original fields remain populated for compatibility with existing JSON users.
	Hostname   string    `json:"hostname"`
	CNAME      string    `json:"cname,omitempty"`
	IPs        []string  `json:"ips"`
	Reachable  bool      `json:"reachable"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	AltNames   []string  `json:"alt_names,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	Issued     time.Time `json:"issued,omitempty"`
	Expiry     time.Time `json:"expiry,omitempty"`
	Error      string    `json:"error,omitempty"`

	ARecords    []string         `json:"a_records,omitempty"`
	AAAARecords []string         `json:"aaaa_records,omitempty"`
	Endpoints   []EndpointResult `json:"endpoints,omitempty"`
	DNS         DNSDetails       `json:"dns"`
	Findings    []Finding        `json:"findings,omitempty"`
	Mail        *MailSecurity    `json:"mail,omitempty"`
	HTTP        *HTTPInspection  `json:"http,omitempty"`
}

type SchemaCapability struct {
	Name             string `json:"name"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	Flag             string `json:"flag,omitempty"`
}

type SchemaCapabilities struct {
	SchemaVersion int                `json:"schema_version"`
	Capabilities  []SchemaCapability `json:"capabilities"`
}
