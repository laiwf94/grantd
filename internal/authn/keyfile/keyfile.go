// Package keyfile reads the PEM files a configuration names: SAML service
// provider keys and certificates, and private CA bundles for provider
// back channels.
package keyfile

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// MinRSABits is the smallest SP key accepted.
const MinRSABits = 2048

// block returns the first PEM block whose type ends in want.
func block(path, want string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: no %s PEM block", path, want)
		}
		if strings.HasSuffix(blk.Type, want) {
			return blk.Bytes, nil
		}
	}
}

// RSAKey reads a PKCS #1 or PKCS #8 RSA private key of at least
// MinRSABits.
func RSAKey(path string) (*rsa.PrivateKey, error) {
	der, err := block(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		key = k
	} else {
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var ok bool
		if key, ok = k.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%s: not an RSA key", path)
		}
	}
	if n := key.N.BitLen(); n < MinRSABits {
		return nil, fmt.Errorf("%s: RSA key has %d bits; at least %d are required", path, n, MinRSABits)
	}
	return key, nil
}

// Certificate reads the first certificate in a PEM file.
func Certificate(path string) (*x509.Certificate, error) {
	der, err := block(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// KeyPair reads an RSA key and the certificate for it.
func KeyPair(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := RSAKey(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := Certificate(certPath)
	if err != nil {
		return nil, nil, err
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("%s does not hold the certificate for %s", certPath, keyPath)
	}
	return key, cert, nil
}

// CAPool reads a bundle of PEM certificates. It returns the certificates
// too, so callers can look at their validity.
func CAPool(path string) (*x509.CertPool, []*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		pool.AddCert(c)
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New(path + ": no PEM certificates")
	}
	return pool, certs, nil
}
