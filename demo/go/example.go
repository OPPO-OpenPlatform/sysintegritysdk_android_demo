package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
)

var rootCerts = []string{
	`-----BEGIN CERTIFICATE-----
MIICvjCCAmOgAwIBAgIOATdmwdl1tSliAs8Z8qwwCgYIKoZIzj0EAwIwPzELMAkG
A1UEBhMCQ04xDjAMBgNVBAoMBU9QbHVzMSAwHgYDVQQDDBdPUGx1cyBHbG9iYWwg
Um9vdCBDQSBFMTAeFw0yMTA2MTYwMzUzMjBaFw00MTA2MTYwMzUzMjBaMFMxCzAJ
BgNVBAYTAkNOMQ4wDAYDVQQKDAVPUGx1czEWMBQGA1UECwwNT1BsdXMgU2Vydmlj
ZTEcMBoGA1UEAwwTT1BsdXMgU2VydmljZSBDQSBFMTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABBOLpHwYzzaZEDJqxjA8ZZvuR2cZ9MsSeSCpiJiLGHS/KxX0SREU
jTqEvf7WO65lFuBZiHx4ELtlQ8KDp5Ap//ujggEtMIIBKTB9BggrBgEFBQcBAQRx
MG8wRQYIKwYBBQUHMAKGOWh0dHA6Ly9vcGx1c3RydXN0LmNvbS9pc3N1ZXIvZ2xv
YmFscm9vdGNhLWUxX2RpZ2ljZXJ0LmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29w
bHVzdHJ1c3QuY29tL29jc3AwHwYDVR0jBBgwFoAUVPh0HOqqnDL2rgyQh7SEFbXT
V+EwDwYDVR0TAQH/BAUwAwEB/zBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vb3Bs
dXN0cnVzdC5jb20vY3JsL2dsb2JhbHJvb3RjYS1lMV9kaWdpY2VydC5jcmwwDgYD
VR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSbVQjSzLnbVMO7XZNNQMCRi0QhoTAKBggq
hkjOPQQDAgNJADBGAiEA7qQibbJ40ICfkPO7W7GGIMfAXIxWUS3AVIMaJoqEdGUC
IQDbSli+zlY29e/2zGrv8EEa7CN9I+woFpLdxzIKlc/Tlg==
-----END CERTIFICATE-----
`,
	`-----BEGIN CERTIFICATE-----
MIIB3jCCAYOgAwIBAgIOAbdFL8C1Bdm3iAjqbBswCgYIKoZIzj0EAwIwPzELMAkG
A1UEBhMCQ04xDjAMBgNVBAoMBU9QbHVzMSAwHgYDVQQDDBdPUGx1cyBHbG9iYWwg
Um9vdCBDQSBFMTAeFw0yMTA2MTYwMzEyMTdaFw00NjA2MTYwMzEyMTdaMD8xCzAJ
BgNVBAYTAkNOMQ4wDAYDVQQKDAVPUGx1czEgMB4GA1UEAwwXT1BsdXMgR2xvYmFs
IFJvb3QgQ0EgRTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQTIV4ip1eRz9EW
CCSo9Mqq5R2pIMrlImXEQjhdru8NscmfYu07XrXYe4BRI5BiirUyXyYcwBrZCCj2
6kd2bIOmo2MwYTAfBgNVHSMEGDAWgBRU+HQc6qqcMvauDJCHtIQVtdNX4TAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUVPh0HOqqnDL2
rgyQh7SEFbXTV+EwCgYIKoZIzj0EAwIDSQAwRgIhAOtjLMghABOi6eZQbo7WP9kA
ENrzyhUrR6y2jYz0enlbAiEApGOOHbSRXyULplrXu6Fc35UUaXQRFmAtldAhHL7Q
/a0=
-----END CERTIFICATE-----
`,
}

type ResponseContent struct {
	BizToken      string   `json:"bizToken"`
	EffectiveTime int64    `json:"effectiveTime"`
	Timestamp     int64    `json:"timestamp"`
	SysIntegrity  bool     `json:"sysIntegrity"`
	OCerts        []string `json:"oCerts"`
	PkgName       string   `json:"pkgName"`
	CertMD5       string   `json:"certMD5"`
	Detail        []string `json:"detail"`
	Advice        []string `json:"advice"`
	Signature     string   `json:"signature"`
}

func main() {
	nonce := "97889e6af58814c61d96d2a27f612f1b"
	rsp := `{"bizToken":"+NWJ/X9IZL+7FX7YLHA2QOF5ZY7D+ONOTIJJPVHD6XQ=","effectiveTime":600,"timestamp":1700116450196,"collectionStrategy":{"interval":86400,"allowAsync":true,"collectionItems":{}},"sysIntegrity":true,"oCerts":["-----BEGIN CERTIFICATE-----\nMIIDWTCCAv+gAwIBAgIOAtnqY6AIr8zYgXyCLxwwCgYIKoZIzj0EAwIwUzELMAkG\nA1UEBhMCQ04xDjAMBgNVBAoMBU9QbHVzMRYwFAYDVQQLDA1PUGx1cyBTZXJ2aWNl\nMRwwGgYDVQQDDBNPUGx1cyBTZXJ2aWNlIENBIEUxMB4XDTIyMTIxOTA2NDYwNloX\nDTI0MDEwMzE0NDYwNlowSzELMAkGA1UEBhMCQ04xDjAMBgNVBAoMBU9QbHVzMRYw\nFAYDVQQLDA1PUGx1cyBTZXJ2aWNlMRQwEgYDVQQDDAtvc2VjLXN0ZHNycDCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ05QYJZo7Tcd8LB86CRisDch94o\na3EO7ex5YlpmWr1T9EhqndZ1G+9dG0J3N+dRq5eEOG9tp5xshaNSiAD7Bke6awjU\nIaeNG8g8GN5VgdAlQa5eX19ajKRbMyEP0hj7E1ZY8y+AQ4f2GQBV/QT2K+xtr73j\nAvtJlt6IkOlV60+eSVI2VxEawAvip+MOElT6AQaKOnH6FNYIHh3z2JW0/7SG/XT2\nyWYJ2InDoiM5jpvj8/zfffRzGmMLU2MmVXmn4q5fI1bTf/MIQetPjtSMrMlaPw2O\n0U6toKktj0GZEeei6qUaopRUL0VakAmjZt5T4OU9rnCwnjecXzMRtTLiL0cCAwEA\nAaOB8zCB8DAfBgNVHSMEGDAWgBSbVQjSzLnbVMO7XZNNQMCRi0QhoTBUBgNVHR8E\nTTBLMEmgR6BFhkNodHRwOi8vZGF0YXNlYy1wa2ktY29uc29sZS1jbi5vcHBvLmxv\nY2FsL2NybC9zZXJ2aWNlLWUxX3NlcnZpY2UuY3JsMCwGA1UdEQQlMCOCIW9tZXMt\nc2VjLXN0ZHNycC1jbi5oZXl0YXBtb2JpLmNvbTALBgNVHQ8EBAMCA8gwHQYDVR0O\nBBYEFNJyknOrdOKK6krqpslbJSf3HsWsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggr\nBgEFBQcDATAKBggqhkjOPQQDAgNIADBFAiA4n5NDubZu423Wq7snSoeZPjBRsmqh\noiyYV6VMRK6V4AIhAPlyeDiDmWiZVM2Qc41OpwcMg2yH9XtalQ7jvsHdVtaA\n-----END CERTIFICATE-----\n"],"pkgName":"com.oplus.srp.demo","certMD5":"a2fa24a06a3cf3f76a3895bc7750fc8d","detail":[],"advice":[],"signature":"OgmhL2e6QjJfJQxo+xpF2fBgvDUGvqM7ZkzzCrK1iw+nfpdjhwOeP8EJGBooFN1pf9P9QjW5Af1wXkZ+Sq8DoI/nnzo79GvFaeLFHJDGcuOmAltrzg/Mbsf7e11T4YxWos+SX9RkphBuWq0JJuJeXwAO41TU+bJrTnL4h5eD7JhIus3QTonxkwWDa14DOLAkzlfbY9dwqpZWRIkVAh8VCJURKmHGScOpxo+BBLAiOhzkv98pMGFEsufpWU4SQBqDF+58C5zDtdby5aJHY6lZiG+Y9H+5v6tOeMbrcF42zg1GbDno2M4XW+UPMaHQc6LJZXz8gYH96KafMn0wtwdv1w=="}`
	var rspContent ResponseContent
	err := json.Unmarshal([]byte(rsp), &rspContent)
	if err != nil {
		log.Println(err)
		return
	}

	// 先验证证书链
	if err = VerifyCertChain(rspContent.OCerts, rootCerts); err != nil {
		log.Println(err)
		return
	}

	// 验签
	if err = VerifySignature(nonce, &rspContent); err != nil {
		log.Println(err)
		return
	}

	log.Println("verified")
}

// 提取公钥
func PublicKeyFromCert(cert []string) (*rsa.PublicKey, error) {
	if len(cert) == 0 {
		return nil, nil
	}

	// 取最后一个证书
	block, _ := pem.Decode([]byte(cert[len(cert)-1]))
	if block == nil {
		return nil, errors.New("pem decode err")
	}

	cf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate err: %v", err)
	}

	pk, ok := cf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid ECDSA public key")
	}

	return pk, nil
}

// 验签
func VerifySignature(nonce string, resContent *ResponseContent) error {
	s64, err := base64.StdEncoding.DecodeString(resContent.Signature)
	if err != nil {
		return fmt.Errorf("base64 decode err: %v", err)
	}

	publicKey, err := PublicKeyFromCert(resContent.OCerts)
	if err != nil {
		return err
	}

	m := make(map[string]string)
	m["nonce"] = nonce
	m["bizToken"] = resContent.BizToken
	m["effectiveTime"] = strconv.FormatInt(resContent.EffectiveTime, 10)
	m["timestamp"] = strconv.FormatInt(resContent.Timestamp, 10)
	m["sysIntegrity"] = strconv.FormatBool(resContent.SysIntegrity)
	m["oCerts"] = strings.Join(resContent.OCerts, ";")
	m["pkgName"] = resContent.PkgName
	m["certMD5"] = resContent.CertMD5
	m["detail"] = strings.Join(resContent.Detail, ";")
	m["advice"] = strings.Join(resContent.Advice, ";")

	// key排序
	key := make([]string, 0, len(m))
	for k := range m {
		key = append(key, k)
	}
	sort.Strings(key)

	var data string
	for _, k := range key {
		data += k + m[k] + ";"
	}
	hashed := sha256.Sum256([]byte(data))
	if err :=rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], s64); err !=nil {
		return errors.New("verify signature failed")
	}

	return nil
}

// 证书链验证
func VerifyCertChain(cert []string, rootCert []string) error {
	if len(cert) == 0 {
		return errors.New("empty cert")
	}


	block, _ := pem.Decode([]byte(cert[len(cert)-1]))
	if block == nil {
		return errors.New("block == nil")
	}

	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate err: %v", err)
	}

	interPool := x509.NewCertPool()
	for i := 0; i < len(cert)-1; i++ {
		if !interPool.AppendCertsFromPEM([]byte(cert[i])) {
			return fmt.Errorf("append inter cert err: %v", err)
		}
	}

	roots := x509.NewCertPool()
	for i := 0; i<len(rootCerts); i++ {
		if !roots.AppendCertsFromPEM([]byte(rootCerts[i])) {
			return fmt.Errorf("append root cert err: %v", err)
		}
	}
	if _, err = ca.Verify(x509.VerifyOptions{Roots: roots, Intermediates: interPool}); err != nil {
		return fmt.Errorf("verify cert chain err: %v", err)
	}

	return nil
}
