package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, blocks ...*pem.Block) string {
		var b []byte
		for _, blk := range blocks {
			b = append(b, pem.EncodeToMemory(blk)...)
		}
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mkCert := func(k *rsa.PrivateKey) []byte {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		return der
	}
	pkcs8 := func(k any) []byte { b, _ := x509.MarshalPKCS8PrivateKey(k); return b }

	pk1 := write("pkcs1.pem", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	// A leading block of another type is skipped.
	pk8 := write("pkcs8.pem", &pem.Block{Type: "CERTIFICATE", Bytes: mkCert(key)}, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(key)})
	crt := write("cert.pem", &pem.Block{Type: "CERTIFICATE", Bytes: mkCert(key)})
	otherCrt := write("other.pem", &pem.Block{Type: "CERTIFICATE", Bytes: mkCert(other)})
	for _, p := range []string{pk1, pk8} {
		if k, c, err := KeyPair(p, crt); err != nil || k == nil || c == nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	bad := map[string]func() error{
		"missing key": func() error { _, err := RSAKey(dir + "/none"); return err },
		"not pem":     func() error { _, err := RSAKey(write("empty.pem")); return err },
		"small key": func() error {
			_, err := RSAKey(write("small.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(small)}))
			return err
		},
		"ec key": func() error {
			_, err := RSAKey(write("ec.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(ec)}))
			return err
		},
		"garbage key": func() error {
			_, err := RSAKey(write("g.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
			return err
		},
		"garbage cert": func() error {
			_, err := Certificate(write("gc.pem", &pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
			return err
		},
		"missing cert": func() error { _, _, err := KeyPair(pk1, dir+"/none"); return err },
		"bad key":      func() error { _, _, err := KeyPair(dir+"/none", crt); return err },
		"mismatch":     func() error { _, _, err := KeyPair(pk1, otherCrt); return err },
		"missing CA":   func() error { _, _, err := CAPool(dir + "/none"); return err },
		"CA no certs":  func() error { _, _, err := CAPool(pk1); return err },
		"CA bad cert": func() error {
			_, _, err := CAPool(write("gca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
			return err
		},
	}
	for name, f := range bad {
		if f() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := func() error {
		_, err := RSAKey(write("s2.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(small)}))
		return err
	}(); !strings.Contains(err.Error(), "1024 bits") {
		t.Errorf("small key error %v", err)
	}
	both := write("bundle.pem", &pem.Block{Type: "CERTIFICATE", Bytes: mkCert(key)}, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(key)},
		&pem.Block{Type: "CERTIFICATE", Bytes: mkCert(other)})
	if pool, certs, err := CAPool(both); err != nil || pool == nil || len(certs) != 2 {
		t.Fatalf("%v %d", err, len(certs))
	}
}
