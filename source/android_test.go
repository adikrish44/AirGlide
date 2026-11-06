package main

import (
	"bytes"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAndroidFirstConnection(t *testing.T) {
	a := newApp(&recorder{}, false)
	a.httpPort, a.httpsPort = 43110, 43111
	a.ips = []net.IP{net.ParseIP("192.168.1.20")}
	var err error
	a.cert, err = prepareCertificate(t.TempDir(), a.ips)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, userAgent string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://192.168.1.20:43110"+path, nil)
		req.RemoteAddr = "192.168.1.80:1234"
		req.Header.Set("User-Agent", userAgent)
		res := httptest.NewRecorder()
		a.plainHandler().ServeHTTP(res, req)
		return res
	}
	for _, tc := range []struct{ query, agent, want string }{
		{"", "Mozilla/5.0 (Linux; Android 14) Chrome", "Download AirGlide-Local.crt"},
		{"&platform=android", "Desktop browser", "Download AirGlide-Local.crt"},
		{"&platform=iphone", "Android", "Download certificate profile"},
		{"", "iPhone", "Download certificate profile"},
	} {
		page := request("/setup?key="+a.setupKey+tc.query, tc.agent)
		if page.Code != 200 || !strings.Contains(page.Body.String(), tc.want) || !strings.Contains(page.Body.String(), "https://192.168.1.20:43111/") {
			t.Fatal("incorrect platform instructions")
		}
	}
	cert := request("/AirGlide-Local.crt?key="+a.setupKey, "Android")
	if cert.Code != 200 || !bytes.Equal(cert.Body.Bytes(), a.cert.RootDER) {
		t.Fatal("wrong Android certificate")
	}
	parsed, err := x509.ParseCertificate(cert.Body.Bytes())
	if err != nil || !parsed.IsCA || parsed.Subject.CommonName != a.cert.Name {
		t.Fatal("invalid Android CA")
	}
	if request("/AirGlide-Local.crt", "Android").Code != 403 {
		t.Fatal("unguarded certificate download")
	}
}
