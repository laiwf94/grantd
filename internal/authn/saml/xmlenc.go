package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // OAEP digests named by XML Encryption
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/beevik/etree"
)

// XML Encryption algorithm identifiers (XML Encryption 1.1).
const (
	EncAES128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	EncAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	KeyRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyRSAOAEP11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"

	digestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	digestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
	mgf1SHA1     = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	mgf1SHA256   = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	mgf1SHA512   = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

var (
	errDecrypt = errors.New("encrypted assertion could not be decrypted")
	// errCBCUnauthenticated is returned for AES-CBC content that no
	// verified signature covers. Decrypting attacker-chosen CBC ciphertext
	// is a padding oracle (Jager and Somorovsky, "How to Break XML
	// Encryption"), so it is refused before any decryption.
	errCBCUnauthenticated = errors.New("AES-CBC encrypted assertions are accepted only inside a signed Response")
)

var keyAlgorithms = map[string]int{EncAES128CBC: 16, EncAES256CBC: 32, EncAES128GCM: 16, EncAES256GCM: 32}

// decryptAssertion decrypts an EncryptedAssertion with the SP's RSA key.
// The content must use AES-GCM, or AES-CBC when outerSigned says a verified
// signature already covers the ciphertext. The key must be transported with
// RSA-OAEP; RSA PKCS#1 v1.5 key transport is refused (Bleichenbacher).
// Every failure after the algorithm checks returns the same error.
func decryptAssertion(ea *etree.Element, key *rsa.PrivateKey, outerSigned bool) ([]byte, error) {
	if key == nil {
		return nil, errors.New("assertion is encrypted but no SP decryption key is configured")
	}
	ed, err := child(ea, NSXEnc, "EncryptedData")
	if err != nil || ed == nil {
		return nil, errors.New("EncryptedAssertion needs exactly one EncryptedData")
	}
	em, err := child(ed, NSXEnc, "EncryptionMethod")
	if err != nil || em == nil {
		return nil, errors.New("EncryptedData has no EncryptionMethod")
	}
	contentAlg := attr(em, "Algorithm")
	keyLen, ok := keyAlgorithms[contentAlg]
	if !ok {
		return nil, errors.New("content encryption algorithm not allowed")
	}
	if strings.HasSuffix(contentAlg, "-cbc") && !outerSigned {
		return nil, errCBCUnauthenticated
	}
	ek, err := findEncryptedKey(ea, ed)
	if err != nil {
		return nil, err
	}
	kem, err := child(ek, NSXEnc, "EncryptionMethod")
	if err != nil || kem == nil {
		return nil, errors.New("EncryptedKey has no EncryptionMethod")
	}
	opts, err := oaepOptions(kem)
	if err != nil {
		return nil, err
	}
	wrapped, err := cipherValue(ek)
	if err != nil {
		return nil, err
	}
	ciphertext, err := cipherValue(ed)
	if err != nil {
		return nil, err
	}
	cek, err := key.Decrypt(rand.Reader, wrapped, opts)
	if err != nil || len(cek) != keyLen {
		return nil, errDecrypt
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, errDecrypt
	}
	if strings.HasSuffix(contentAlg, "-gcm") {
		// XML Encryption 1.1 section 5.2.4: IV (96 bits) || ciphertext || tag.
		gcm, err := cipher.NewGCM(block)
		if err != nil || len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
			return nil, errDecrypt
		}
		pt, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
		if err != nil {
			return nil, errDecrypt
		}
		return pt, nil
	}
	// CBC: IV || ciphertext, with XML Encryption padding (the last byte is
	// the pad length; the other pad bytes are arbitrary).
	if len(ciphertext) < 2*aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	pt := make([]byte, len(ciphertext)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, ciphertext[:aes.BlockSize]).CryptBlocks(pt, ciphertext[aes.BlockSize:])
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize {
		return nil, errDecrypt
	}
	return pt[:len(pt)-pad], nil
}

// findEncryptedKey accepts the key inside EncryptedData's KeyInfo or as a
// sibling of EncryptedData, but exactly one in total.
func findEncryptedKey(ea, ed *etree.Element) (*etree.Element, error) {
	var found []*etree.Element
	if ki, err := child(ed, NSDSig, "KeyInfo"); err != nil {
		return nil, err
	} else if ki != nil {
		found = append(found, children(ki, NSXEnc, "EncryptedKey")...)
	}
	found = append(found, children(ea, NSXEnc, "EncryptedKey")...)
	if len(found) != 1 {
		return nil, errors.New("expected exactly one EncryptedKey")
	}
	return found[0], nil
}

func oaepOptions(kem *etree.Element) (*rsa.OAEPOptions, error) {
	hashes := map[string]crypto.Hash{digestSHA1: crypto.SHA1, digestSHA256: crypto.SHA256, digestSHA512: crypto.SHA512}
	mgfs := map[string]crypto.Hash{mgf1SHA1: crypto.SHA1, mgf1SHA256: crypto.SHA256, mgf1SHA512: crypto.SHA512}
	opts := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
	if dm, err := child(kem, NSDSig, "DigestMethod"); err != nil {
		return nil, err
	} else if dm != nil {
		h, ok := hashes[attr(dm, "Algorithm")]
		if !ok {
			return nil, errors.New("OAEP digest not allowed")
		}
		opts.Hash = h
	}
	switch attr(kem, "Algorithm") {
	case KeyRSAOAEP:
		// MGF1 with SHA-1 is fixed by this identifier.
	case KeyRSAOAEP11:
		if mgf, err := child(kem, NSXEnc11, "MGF"); err != nil {
			return nil, err
		} else if mgf != nil {
			h, ok := mgfs[attr(mgf, "Algorithm")]
			if !ok {
				return nil, errors.New("OAEP mask generation function not allowed")
			}
			opts.MGFHash = h
		}
	default:
		return nil, errors.New("key transport algorithm not allowed (RSA-OAEP only)")
	}
	return opts, nil
}

func cipherValue(el *etree.Element) ([]byte, error) {
	cd, err := child(el, NSXEnc, "CipherData")
	if err != nil || cd == nil {
		return nil, errors.New("missing CipherData")
	}
	cv, err := child(cd, NSXEnc, "CipherValue")
	if err != nil || cv == nil {
		return nil, errors.New("missing CipherValue (CipherReference is not supported)")
	}
	t, err := text(cv)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(t), ""))
	if err != nil {
		return nil, errors.New("CipherValue is not base64")
	}
	return b, nil
}
