package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func certificateInfo(cert *x509.Certificate, now time.Time) CertificateInfo {
	sum := sha256.Sum256(cert.Raw)
	info := CertificateInfo{
		Subject:                cert.Subject.String(),
		Issuer:                 cert.Issuer.String(),
		AltNames:               append([]string(nil), cert.DNSNames...),
		Issued:                 cert.NotBefore,
		Expiry:                 cert.NotAfter,
		DaysRemaining:          daysRemaining(now, cert.NotAfter),
		TimeStatus:             certificateTimeStatus(cert, now),
		SerialNumber:           strings.ToUpper(cert.SerialNumber.Text(16)),
		FingerprintSHA256:      colonHex(sum[:]),
		PublicKeyAlgorithm:     cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm:     cert.SignatureAlgorithm.String(),
		KeyUsage:               keyUsageStrings(cert.KeyUsage),
		ExtendedKeyUsage:       extendedKeyUsageStrings(cert.ExtKeyUsage),
		IsCA:                   cert.IsCA,
		OCSPServers:            append([]string(nil), cert.OCSPServer...),
		CRLDistributionPoints:  append([]string(nil), cert.CRLDistributionPoints...),
		IssuingCertificateURLs: append([]string(nil), cert.IssuingCertificateURL...),
	}
	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			info.WildcardAltNames = append(info.WildcardAltNames, name)
		}
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = key.Curve.Params().BitSize
		info.PublicKeyCurve = key.Curve.Params().Name
	case ed25519.PublicKey:
		info.PublicKeyBits = len(key) * 8
	}
	tlsFeatureOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(tlsFeatureOID) {
			continue
		}
		var features []int
		if _, err := asn1.Unmarshal(extension.Value, &features); err == nil {
			info.TLSFeatures = features
			for _, feature := range features {
				if feature == 5 {
					info.MustStaple = true
				}
			}
		}
	}
	return info
}

func certificateTimeStatus(cert *x509.Certificate, now time.Time) string {
	if now.Before(cert.NotBefore) {
		return "not_yet_valid"
	}
	if now.After(cert.NotAfter) {
		return "expired"
	}
	return "valid"
}

func daysRemaining(now, expiry time.Time) int {
	duration := expiry.Sub(now)
	if duration >= 0 {
		return int((duration + 24*time.Hour - 1) / (24 * time.Hour))
	}
	return -int((-duration + 24*time.Hour - 1) / (24 * time.Hour))
}

func colonHex(data []byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(data))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}

func keyUsageStrings(usage x509.KeyUsage) []string {
	values := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "certificate_signing"},
		{x509.KeyUsageCRLSign, "crl_signing"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	var result []string
	for _, value := range values {
		if usage&value.flag != 0 {
			result = append(result, value.name)
		}
	}
	return result
}

func extendedKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "any",
		x509.ExtKeyUsageServerAuth:                     "server_auth",
		x509.ExtKeyUsageClientAuth:                     "client_auth",
		x509.ExtKeyUsageCodeSigning:                    "code_signing",
		x509.ExtKeyUsageEmailProtection:                "email_protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "ipsec_end_system",
		x509.ExtKeyUsageIPSECTunnel:                    "ipsec_tunnel",
		x509.ExtKeyUsageIPSECUser:                      "ipsec_user",
		x509.ExtKeyUsageTimeStamping:                   "time_stamping",
		x509.ExtKeyUsageOCSPSigning:                    "ocsp_signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoft_server_gated_crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscape_server_gated_crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoft_commercial_code_signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoft_kernel_code_signing",
	}
	result := make([]string, 0, len(usages))
	for _, usage := range usages {
		if name, ok := names[usage]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("unknown_%d", usage))
		}
	}
	return result
}
