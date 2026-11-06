package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Certificate struct {
	CertFile, KeyFile string
	RootDER           []byte
	Fingerprint, Name string
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}
func newUUID() string {
	s := randomHex(16)
	return s[:8] + "-" + s[8:12] + "-4" + s[13:16] + "-a" + s[17:20] + "-" + s[20:]
}

func prepareCertificate(dir string, ips []net.IP) (Certificate, error) {
	c := Certificate{CertFile: filepath.Join(dir, "server.pem"), KeyFile: filepath.Join(dir, "server-key.pem")}
	rootPath := filepath.Join(dir, "root.cer")
	root, rootErr := os.ReadFile(rootPath)
	leaf, leafErr := os.ReadFile(c.CertFile)
	if rootErr == nil && leafErr == nil {
		block, _ := pem.Decode(leaf)
		if block != nil {
			p, e := x509.ParseCertificate(block.Bytes)
			valid := e == nil && time.Until(p.NotAfter) > 7*24*time.Hour
			if valid {
				for _, ip := range ips {
					if p.VerifyHostname(ip.String()) != nil {
						valid = false
					}
				}
			}
			if _, e = os.Stat(c.KeyFile); e != nil {
				valid = false
			}
			if valid {
				c.RootDER = root
				return finishCertificate(c)
			}
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return c, err
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return c, err
	}
	now := time.Now()
	name := "AirGlide Local " + strings.ToUpper(randomHex(3))
	rt := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root, err = x509.CreateCertificate(rand.Reader, rt, rt, &rootKey.PublicKey, rootKey)
	if err != nil {
		return c, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return c, err
	}
	lt := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "AirGlide on your PC"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(180 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: ips}
	der, err := x509.CreateCertificate(rand.Reader, lt, rt, &leafKey.PublicKey, rootKey)
	if err != nil {
		return c, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return c, err
	}
	// Deliberately never persist the root signing key. A changed PC IP creates
	// a new certificate/profile instead of retaining a general-purpose CA key.
	for path, data := range map[string][]byte{c.CertFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.KeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), rootPath: root} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			return c, err
		}
	}
	c.RootDER = root
	return finishCertificate(c)
}
func finishCertificate(c Certificate) (Certificate, error) {
	p, e := x509.ParseCertificate(c.RootDER)
	if e != nil {
		return c, e
	}
	c.Name = p.Subject.CommonName
	sum := sha256.Sum256(c.RootDER)
	c.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	return c, nil
}
func (c Certificate) profile() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadCertificateFileName</key><string>AirGlide.cer</string>
<key>PayloadContent</key><data>%s</data>
<key>PayloadDescription</key><string>Enables an encrypted connection to your AirGlide Windows companion. No device management, VPN, or account settings.</string>
<key>PayloadDisplayName</key><string>%s</string>
<key>PayloadIdentifier</key><string>local.airremote.certificate</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>%s</string><key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>%s</string>
<key>PayloadDescription</key><string>Local certificate for the AirGlide app on your Windows PC. Remove this profile when you stop using the app.</string>
<key>PayloadIdentifier</key><string>local.airremote.profile.%s</string>
<key>PayloadOrganization</key><string>AirGlide on your PC</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>%s</string><key>PayloadVersion</key><integer>1</integer>
</dict></plist>`, base64.StdEncoding.EncodeToString(c.RootDER), c.Name, newUUID(), c.Name, c.Fingerprint[:12], newUUID())
}
