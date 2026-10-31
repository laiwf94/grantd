package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	spEntity = "https://gw.test/saml/partner/metadata"
	acsURL   = "https://gw.test/saml/partner/acs"
	reqID    = "_0123456789abcdef0123456789abcdef"
)

var (
	spKey, _  = rsa.GenerateKey(rand.Reader, 2048)
	spCert, _ = fakeidp.SelfSignedCert(spKey, "sp", time.Now())
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t   testing.TB
	idp *fakeidp.IdP
	sp  *SP
	clk *clock
	md  *IdPMetadata
}

func newEnv(t testing.TB) *env {
	t.Helper()
	clk := &clock{t: time.Now()}
	idp, err := fakeidp.New(fakeidp.Config{Issuer: "https://idp.test", Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	md, err := ParseIdPMetadata(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, idp: idp, clk: clk, md: md}
	e.sp = e.newSP(nil)
	return e
}

func (e *env) newSP(mutate func(*Config)) *SP {
	e.t.Helper()
	cfg := Config{ProviderID: "partner", EntityID: spEntity, ACSURL: acsURL, IdP: e.md, Key: spKey, Cert: spCert,
		EmailAttr: "email", NameAttr: "displayName", GroupsAttr: "groups", Now: e.clk.now}
	if mutate != nil {
		mutate(&cfg)
	}
	sp, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return sp
}

type respOpts struct {
	signResponse, signAssertion bool
	encrypt, cbc                bool
	acs, audience, inResponseTo string
	beforeSign                  func(a *etree.Element)
}

func (e *env) doc(o respOpts) *etree.Document {
	e.t.Helper()
	sp := fakeidp.ServiceProvider{EntityID: spEntity, ACSURL: acsURL, SignResponse: o.signResponse, SignAssertion: o.signAssertion}
	if o.acs != "" {
		sp.ACSURL = o.acs
	}
	if o.audience != "" {
		sp.EntityID = o.audience
	}
	if o.encrypt {
		sp.EncryptCert = spCert
	}
	irt := reqID
	if o.inResponseTo != "" {
		irt = o.inResponseTo
	}
	doc, err := e.idp.SAMLResponseDoc(fakeidp.ResponseOptions{SP: sp, InResponseTo: irt, User: fakeidp.DemoUsers[2],
		EncryptCBC: o.cbc, BeforeSign: o.beforeSign})
	if err != nil {
		e.t.Fatal(err)
	}
	return doc
}

func encode(t testing.TB, doc *etree.Document) string {
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// find returns the first element with this local name, depth first.
func find(el *etree.Element, tag string) *etree.Element {
	if el.Tag == tag {
		return el
	}
	for _, c := range el.ChildElements() {
		if f := find(c, tag); f != nil {
			return f
		}
	}
	return nil
}

func directChild(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

func reasonOf(err error) string {
	var se *Error
	if errors.As(err, &se) {
		return se.Reason
	}
	return ""
}

func TestValidResponses(t *testing.T) {
	e := newEnv(t)
	cases := map[string]respOpts{
		"assertion signed":                {signAssertion: true},
		"response signed":                 {signResponse: true},
		"both signed":                     {signResponse: true, signAssertion: true},
		"encrypted GCM":                   {signAssertion: true, encrypt: true},
		"encrypted CBC, signed resp":      {signResponse: true, signAssertion: true, encrypt: true, cbc: true},
		"encrypted, response signed only": {signResponse: true, encrypt: true},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := e.sp.ParseResponse(encode(t, e.doc(o)), reqID)
			if err != nil {
				t.Fatal(err)
			}
			id := res.Identity
			if id.Subject != "carol@partner.example" || id.Email != "carol@partner.example" || id.Name != "Carol" ||
				len(id.Groups) != 1 || id.Groups[0] != "eng" || id.Provider != "partner" || res.SessionNotOnOrAfter.IsZero() {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestInheritedNamespace: an assertion that relies on a namespace declared
// on the Response must still verify once detached (the canonical form the
// IdP signed declares it on the assertion).
func TestInheritedNamespace(t *testing.T) {
	e := newEnv(t)
	doc := e.doc(respOpts{signAssertion: true})
	a := directChild(doc.Root(), "Assertion")
	a.RemoveAttr("xmlns:saml")
	if a.SelectAttr("xmlns:saml") != nil {
		t.Fatal("setup")
	}
	if _, err := e.sp.ParseResponse(encode(t, doc), reqID); err != nil {
		t.Fatal(err)
	}
}

// signWith re-signs el (dropping any old signature) with the IdP key and
// the given method.
func signWith(t testing.TB, e *env, el *etree.Element, method string) *etree.Element {
	t.Helper()
	if s := directChild(el, "Signature"); s != nil {
		el.RemoveChild(s)
	}
	ctx, err := dsig.NewSigningContext(e.idp.SigningKey(), [][]byte{e.idp.Certificate().Raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(method); err != nil {
		t.Fatal(err)
	}
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		t.Fatal(err)
	}
	out := el.Copy()
	out.InsertChildAt(1, sig)
	return out
}

func replace(parent, old, new *etree.Element) {
	idx := old.Index()
	parent.RemoveChildAt(idx)
	parent.InsertChildAt(idx, new)
}

func evilClone(signed *etree.Element) *etree.Element {
	evil := signed.Copy()
	if s := directChild(evil, "Signature"); s != nil {
		evil.RemoveChild(s)
	}
	find(evil, "NameID").SetText("admin@partner.example")
	return evil
}

// TestAttacks is the SAML attack suite: each case builds a response the
// way an attacker would and names the rejection it must get.
func TestAttacks(t *testing.T) {
	cases := []struct {
		name   string
		build  func(e *env) (string, string) // response, request ID
		reason string
	}{
		{"XSW1: evil assertion beside the signed one", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			a := directChild(doc.Root(), "Assertion")
			doc.Root().AddChild(evilClone(a))
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW2: signed assertion hidden in Extensions, evil one in its place", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			root := doc.Root()
			a := directChild(root, "Assertion")
			root.RemoveChild(a)
			ext := etree.NewElement("samlp:Extensions")
			ext.AddChild(a)
			root.InsertChildAt(1, ext)
			root.AddChild(evilClone(a))
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW3: signed assertion inside the evil assertion's Advice", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			root := doc.Root()
			a := directChild(root, "Assertion")
			evil := evilClone(a)
			adv := evil.CreateElement("saml:Advice")
			adv.AddChild(a.Copy())
			replace(root, a, evil)
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW4: evil assertion takes the signed one's ID and signature", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			root := doc.Root()
			a := directChild(root, "Assertion")
			evil := a.Copy()
			find(evil, "NameID").SetText("admin@partner.example")
			// Keep the original, renamed, so its bytes are still there to
			// be digested if a verifier looked it up by ID.
			orig := a.Copy()
			orig.Tag = "OriginalAssertion"
			ext := etree.NewElement("samlp:Extensions")
			ext.AddChild(orig)
			replace(root, a, evil)
			root.InsertChildAt(1, ext)
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW5: Reference points at another element", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			find(doc.Root(), "Reference").CreateAttr("URI", "#_somewhere_else")
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW6: extra Reference in SignedInfo", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			si := find(doc.Root(), "SignedInfo")
			si.AddChild(find(si, "Reference").Copy())
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW7: signed Response nested inside an evil Response", func(e *env) (string, string) {
			signed := e.doc(respOpts{signResponse: true}).Root()
			evil := signed.Copy()
			if s := directChild(evil, "Signature"); s != nil {
				evil.RemoveChild(s)
			}
			evil.CreateAttr("ID", "_evil_response")
			ext := etree.NewElement("samlp:Extensions")
			ext.AddChild(signed)
			evil.InsertChildAt(1, ext)
			find(directChild(evil, "Assertion"), "NameID").SetText("admin@partner.example")
			doc := etree.NewDocument()
			doc.SetRoot(evil)
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"XSW8: signed Response nested, no assertion at the top", func(e *env) (string, string) {
			signed := e.doc(respOpts{signResponse: true}).Root()
			evil := etree.NewElement("samlp:Response")
			for _, a := range signed.Attr {
				evil.CreateAttr(a.FullKey(), a.Value)
			}
			evil.CreateAttr("ID", "_evil_response")
			evil.AddChild(directChild(signed, "Issuer").Copy())
			evil.AddChild(directChild(signed, "Status").Copy())
			ext := evil.CreateElement("samlp:Extensions")
			ext.AddChild(signed)
			doc := etree.NewDocument()
			doc.SetRoot(evil)
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"two signatures on one assertion", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			a := directChild(doc.Root(), "Assertion")
			a.AddChild(directChild(a, "Signature").Copy())
			return encode(e.t, doc), reqID
		}, ReasonWrapping},
		{"signature stripped", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			a := directChild(doc.Root(), "Assertion")
			a.RemoveChild(directChild(a, "Signature"))
			return encode(e.t, doc), reqID
		}, ReasonUnsigned},
		{"never signed", func(e *env) (string, string) { return encode(e.t, e.doc(respOpts{})), reqID }, ReasonUnsigned},
		{"NameID changed after signing", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			find(doc.Root(), "NameID").SetText("admin@partner.example")
			return encode(e.t, doc), reqID
		}, ReasonSignature},
		{"group added after response signing", func(e *env) (string, string) {
			doc := e.doc(respOpts{signResponse: true})
			v := find(doc.Root(), "AttributeValue").Copy()
			v.SetText("admins")
			find(doc.Root(), "AttributeStatement").ChildElements()[2].AddChild(v)
			return encode(e.t, doc), reqID
		}, ReasonSignature},
		{"signed by the attacker's own key and certificate", func(e *env) (string, string) {
			attacker, _ := fakeidp.New(fakeidp.Config{Issuer: "https://idp.test", Now: e.clk.now})
			doc, _ := attacker.SAMLResponseDoc(fakeidp.ResponseOptions{SP: fakeidp.ServiceProvider{EntityID: spEntity,
				ACSURL: acsURL, SignAssertion: true}, InResponseTo: reqID, User: fakeidp.DemoUsers[0]})
			return encode(e.t, doc), reqID
		}, ReasonSignature},
		{"RSA-SHA1 signature", func(e *env) (string, string) {
			doc := e.doc(respOpts{})
			a := directChild(doc.Root(), "Assertion")
			replace(doc.Root(), a, signWith(e.t, e, a, dsig.RSASHA1SignatureMethod))
			return encode(e.t, doc), reqID
		}, ReasonSignature},
		{"comment splits the NameID (CVE-2017-11427 class)", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true, beforeSign: func(a *etree.Element) {
				find(a, "NameID").SetText("carol@partner.example.evil.com")
			}})
			nid := find(doc.Root(), "NameID")
			nid.Child = nil
			nid.CreateText("carol@partner.example")
			nid.CreateComment("")
			nid.CreateText(".evil.com")
			return encode(e.t, doc), reqID
		}, ReasonMalformed},
		{"DOCTYPE with an entity", func(e *env) (string, string) {
			b, _ := e.doc(respOpts{signAssertion: true}).WriteToBytes()
			b = append([]byte(`<!DOCTYPE r [<!ENTITY x "y">]>`), b...)
			return base64.StdEncoding.EncodeToString(b), reqID
		}, ReasonMalformed},
		{"processing instruction", func(e *env) (string, string) {
			b, _ := e.doc(respOpts{signAssertion: true}).WriteToBytes()
			b = append([]byte(`<?xml version="1.0"?><?evil x?>`), b...)
			return base64.StdEncoding.EncodeToString(b), reqID
		}, ReasonMalformed},
		{"wrong Destination", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signResponse: true, acs: "https://evil.test/acs"})), reqID
		}, ReasonDestination},
		{"wrong Recipient", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true, acs: "https://evil.test/acs"})
			doc.Root().CreateAttr("Destination", acsURL)
			return encode(e.t, doc), reqID
		}, ReasonRecipient},
		{"wrong Audience", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true, audience: "https://other-sp.test"})), reqID
		}, ReasonAudience},
		{"second AudienceRestriction excludes us", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true, beforeSign: func(a *etree.Element) {
				find(a, "Conditions").CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText("https://other")
			}})), reqID
		}, ReasonAudience},
		{"answer to another request (response InResponseTo)", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true})), "_another_request_id_0000000000000"
		}, ReasonInResponseTo},
		{"answer to another request (assertion InResponseTo)", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true, inResponseTo: "_another_request_id_0000000000000"})
			doc.Root().RemoveAttr("InResponseTo")
			return encode(e.t, doc), reqID
		}, ReasonInResponseTo},
		{"IdP-initiated (unsolicited)", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true})), ""
		}, ReasonUnsolicited},
		{"IdP status is a failure", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true})
			find(doc.Root(), "StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")
			return encode(e.t, doc), reqID
		}, ReasonStatus},
		{"bearer confirmation with NotBefore", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true, beforeSign: func(a *etree.Element) {
				find(a, "SubjectConfirmationData").CreateAttr("NotBefore", "2000-01-01T00:00:00Z")
			}})), reqID
		}, ReasonSubject},
		{"attribute value with markup", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true, beforeSign: func(a *etree.Element) {
				find(a, "AttributeValue").CreateElement("b").SetText("x")
			}})), reqID
		}, ReasonAttributes},
		{"CBC-encrypted assertion without a signed Response", func(e *env) (string, string) {
			return encode(e.t, e.doc(respOpts{signAssertion: true, encrypt: true, cbc: true})), reqID
		}, ReasonEncrypted},
		{"tampered GCM ciphertext", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true, encrypt: true})
			cvs := doc.Root().FindElements("//CipherValue")
			ct, _ := base64.StdEncoding.DecodeString(cvs[1].Text())
			ct[len(ct)-1] ^= 1
			cvs[1].SetText(base64.StdEncoding.EncodeToString(ct))
			return encode(e.t, doc), reqID
		}, ReasonEncrypted},
		{"RSA PKCS#1 v1.5 key transport", func(e *env) (string, string) {
			doc := e.doc(respOpts{signAssertion: true, encrypt: true})
			ek := find(doc.Root(), "EncryptedKey")
			find(ek, "EncryptionMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-1_5")
			return encode(e.t, doc), reqID
		}, ReasonEncrypted},
		{"not base64", func(e *env) (string, string) { return "!!!", reqID }, ReasonMalformed},
		{"not a Response", func(e *env) (string, string) {
			return base64.StdEncoding.EncodeToString([]byte(`<a/>`)), reqID
		}, ReasonMalformed},
		{"too large", func(e *env) (string, string) { return strings.Repeat("A", maxEncodedResponse+4), reqID }, ReasonMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			resp, id := c.build(e)
			res, err := e.sp.ParseResponse(resp, id)
			if err == nil {
				t.Fatalf("accepted: %+v", res)
			}
			if got := reasonOf(err); got != c.reason {
				t.Fatalf("reason %q (%v), want %q", got, err, c.reason)
			}
		})
	}
}

func TestReplayAndTime(t *testing.T) {
	e := newEnv(t)
	resp := encode(t, e.doc(respOpts{signAssertion: true}))
	if _, err := e.sp.ParseResponse(resp, reqID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sp.ParseResponse(resp, reqID); reasonOf(err) != ReasonReplay {
		t.Fatalf("replay: %v", err)
	}
	// A rebuilt SP sharing the cache (as after a config reload) still
	// refuses it.
	shared := e.newSP(func(c *Config) { c.Replay = e.sp.cfg.Replay })
	if _, err := shared.ParseResponse(resp, reqID); reasonOf(err) != ReasonReplay {
		t.Fatalf("replay after reload: %v", err)
	}

	late := encode(t, e.doc(respOpts{signAssertion: true}))
	e.clk.add(8 * time.Minute)
	if _, err := e.sp.ParseResponse(late, reqID); reasonOf(err) != ReasonExpired {
		t.Fatalf("expired: %v", err)
	}
	early := encode(t, e.doc(respOpts{signAssertion: true}))
	e.clk.add(-20 * time.Minute)
	if _, err := e.sp.ParseResponse(early, reqID); reasonOf(err) != ReasonNotYetValid {
		t.Fatalf("not yet valid: %v", err)
	}
}

func TestWrongIssuerAndKeys(t *testing.T) {
	e := newEnv(t)
	other := *e.md
	other.EntityID = "https://someone-else.test"
	sp := e.newSP(func(c *Config) { c.IdP = &other })
	if _, err := sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true})), reqID); reasonOf(err) != ReasonIssuer {
		t.Fatalf("issuer: %v", err)
	}
	if _, err := sp.ParseResponse(encode(t, e.doc(respOpts{signResponse: true})), reqID); reasonOf(err) != ReasonIssuer {
		t.Fatalf("response issuer: %v", err)
	}
	noKey := e.newSP(func(c *Config) { c.Key, c.Cert = nil, nil })
	if _, err := noKey.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true, encrypt: true})), reqID); reasonOf(err) != ReasonEncrypted {
		t.Fatalf("no key: %v", err)
	}
}

func TestDecryptVariants(t *testing.T) {
	// Build EncryptedAssertion elements by hand to reach every branch of
	// the XML Encryption parser.
	plain := []byte(`<saml:Assertion xmlns:saml="` + NSAssertion + `" ID="_a" Version="2.0"/>`)
	cek := make([]byte, 16)
	rand.Read(cek)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	gcmCT := gcm.Seal(nonce, nonce, plain, nil)
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(16 - len(plain)%16)}, 16-len(plain)%16)...)
	cbcCT := make([]byte, 16+len(padded))
	cipher.NewCBCEncrypter(block, cbcCT[:16]).CryptBlocks(cbcCT[16:], padded)
	// cbcWithLastByte encrypts plain padded to a block boundary whose final
	// byte (the pad length) is b, so invalid padding is built on purpose
	// rather than hoped for from random bytes.
	cbcWithLastByte := func(b byte) []byte {
		p := append(append([]byte{}, plain...), make([]byte, 16-len(plain)%16)...)
		p[len(p)-1] = b
		ct := make([]byte, 16+len(p))
		cipher.NewCBCEncrypter(block, ct[:16]).CryptBlocks(ct[16:], p)
		return ct
	}
	wrap := func(h crypto.Hash, mgf crypto.Hash) []byte {
		w, err := rsa.EncryptOAEPWithOptions(rand.Reader, &spKey.PublicKey, cek, &rsa.OAEPOptions{Hash: h, MGFHash: mgf})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	wrapOther := func() []byte {
		other := make([]byte, 16)
		rand.Read(other)
		w, _ := rsa.EncryptOAEPWithOptions(rand.Reader, &spKey.PublicKey, other, &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1})
		return w
	}
	type spec struct {
		content, keyAlg, digest, mgf string
		wrapped, ct                  []byte
		sibling                      bool
	}
	build := func(s spec) *etree.Element {
		ea := etree.NewElement("saml:EncryptedAssertion")
		ea.CreateAttr("xmlns:saml", NSAssertion)
		ea.CreateAttr("xmlns:ds", NSDSig)
		ed := ea.CreateElement("xenc:EncryptedData")
		ed.CreateAttr("xmlns:xenc", NSXEnc)
		ed.CreateAttr("xmlns:xenc11", NSXEnc11)
		ed.CreateAttr("xmlns:ds", NSDSig)
		ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", s.content)
		parent := ed.CreateElement("ds:KeyInfo")
		if s.sibling {
			parent = ea
		}
		ek := parent.CreateElement("xenc:EncryptedKey")
		ek.CreateAttr("xmlns:xenc", NSXEnc)
		em := ek.CreateElement("xenc:EncryptionMethod")
		em.CreateAttr("Algorithm", s.keyAlg)
		if s.digest != "" {
			em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", s.digest)
		}
		if s.mgf != "" {
			m := em.CreateElement("xenc11:MGF")
			m.CreateAttr("xmlns:xenc11", NSXEnc11)
			m.CreateAttr("Algorithm", s.mgf)
		}
		ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(s.wrapped))
		ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(s.ct))
		doc := etree.NewDocument()
		doc.SetRoot(ea)
		b, _ := doc.WriteToBytes()
		d, err := parseStrict(b)
		if err != nil {
			t.Fatal(err)
		}
		return d.Root()
	}
	ok := []spec{
		{content: EncAES128GCM, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT},
		{content: EncAES128GCM, keyAlg: KeyRSAOAEP, digest: digestSHA256, wrapped: wrap(crypto.SHA256, crypto.SHA1), ct: gcmCT, sibling: true},
		{content: EncAES128GCM, keyAlg: KeyRSAOAEP11, digest: digestSHA256, mgf: mgf1SHA256, wrapped: wrap(crypto.SHA256, crypto.SHA256), ct: gcmCT},
		{content: EncAES128CBC, keyAlg: KeyRSAOAEP11, digest: digestSHA512, wrapped: wrap(crypto.SHA512, crypto.SHA1), ct: cbcCT},
	}
	for i, s := range ok {
		pt, err := decryptAssertion(build(s), spKey, true)
		if err != nil || !bytes.Equal(pt, plain) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	bad := map[string]spec{
		"unknown content alg": {content: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT},
		"key size mismatch":   {content: EncAES256GCM, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT},
		"wrong OAEP digest":   {content: EncAES128GCM, keyAlg: KeyRSAOAEP, digest: digestSHA256, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT},
		"unknown digest":      {content: EncAES128GCM, keyAlg: KeyRSAOAEP, digest: "urn:md5", wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT},
		"unknown mgf":         {content: EncAES128GCM, keyAlg: KeyRSAOAEP11, mgf: "urn:mgf", wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT},
		"short GCM":           {content: EncAES128GCM, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: gcmCT[:20]},
		"short CBC":           {content: EncAES128CBC, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: cbcCT[:16]},
		"ragged CBC":          {content: EncAES128CBC, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: cbcCT[:40]},
		"CBC pad length 0":    {content: EncAES128CBC, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: cbcWithLastByte(0)},
		"CBC pad length 17":   {content: EncAES128CBC, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: cbcWithLastByte(17)},
		"CBC pad length 255":  {content: EncAES128CBC, keyAlg: KeyRSAOAEP, wrapped: wrap(crypto.SHA1, crypto.SHA1), ct: cbcWithLastByte(255)},
		"wrong content key":   {content: EncAES128GCM, keyAlg: KeyRSAOAEP, wrapped: wrapOther(), ct: gcmCT},
	}
	// Everything that fails after the algorithm checks (key unwrap, GCM tag,
	// CBC padding, lengths) must fail with the same error, or the
	// differences become a decryption oracle.
	sameError := map[string]bool{"wrong OAEP digest": true, "key size mismatch": true, "short GCM": true,
		"short CBC": true, "ragged CBC": true, "CBC pad length 0": true, "CBC pad length 17": true,
		"CBC pad length 255": true, "wrong content key": true}
	for name, s := range bad {
		_, err := decryptAssertion(build(s), spKey, true)
		if err == nil {
			t.Errorf("%s: decrypted", name)
		} else if sameError[name] && !errors.Is(err, errDecrypt) {
			t.Errorf("%s: distinguishable error %v", name, err)
		}
	}
	// Structural problems.
	for name, x := range map[string]string{
		"no EncryptedData":   `<saml:EncryptedAssertion xmlns:saml="` + NSAssertion + `"/>`,
		"no method":          `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData/></a>`,
		"no key":             `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData><x:EncryptionMethod Algorithm="` + EncAES128GCM + `"/></x:EncryptedData></a>`,
		"two keys":           `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData><x:EncryptionMethod Algorithm="` + EncAES128GCM + `"/></x:EncryptedData><x:EncryptedKey/><x:EncryptedKey/></a>`,
		"key without method": `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData><x:EncryptionMethod Algorithm="` + EncAES128GCM + `"/></x:EncryptedData><x:EncryptedKey/></a>`,
		"no cipher data":     `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData><x:EncryptionMethod Algorithm="` + EncAES128GCM + `"/></x:EncryptedData><x:EncryptedKey><x:EncryptionMethod Algorithm="` + KeyRSAOAEP + `"/></x:EncryptedKey></a>`,
		"cipher reference":   `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData><x:EncryptionMethod Algorithm="` + EncAES128GCM + `"/></x:EncryptedData><x:EncryptedKey><x:EncryptionMethod Algorithm="` + KeyRSAOAEP + `"/><x:CipherData><x:CipherReference/></x:CipherData></x:EncryptedKey></a>`,
		"bad base64":         `<a xmlns:x="` + NSXEnc + `"><x:EncryptedData><x:EncryptionMethod Algorithm="` + EncAES128GCM + `"/></x:EncryptedData><x:EncryptedKey><x:EncryptionMethod Algorithm="` + KeyRSAOAEP + `"/><x:CipherData><x:CipherValue>!!</x:CipherValue></x:CipherData></x:EncryptedKey></a>`,
	} {
		d, err := parseStrict([]byte(x))
		if err != nil {
			t.Fatal(name, err)
		}
		if _, err := decryptAssertion(d.Root(), spKey, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseStrict(t *testing.T) {
	for name, x := range map[string]string{
		"two roots":      `<a/><b/>`,
		"text outside":   `<a/>text`,
		"empty":          ``,
		"unclosed":       `<a>`,
		"deep":           strings.Repeat("<a>", maxXMLDepth+1) + strings.Repeat("</a>", maxXMLDepth+1),
		"unknown entity": `<a>&evil;</a>`,
		"huge":           "<a>" + strings.Repeat("x", MaxXMLBytes) + "</a>",
		"many tokens":    "<a>" + strings.Repeat("<b/>", maxXMLTokens) + "</a>",
	} {
		if _, err := parseStrict([]byte(x)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := parseStrict([]byte(`<?xml version="1.0"?>` + "\n<a>ok</a>\n")); err != nil {
		t.Fatal(err)
	}
	d, _ := parseStrict([]byte(`<a>x<![CDATA[y]]>z</a>`))
	if s, err := text(d.Root()); err != nil || s != "xyz" {
		t.Fatalf("split character data: %q %v", s, err)
	}
	d, _ = parseStrict([]byte(`<a><x:b xmlns:x="u"/><x:b xmlns:x="u"/></a>`))
	if _, err := child(d.Root(), "u", "b"); err == nil {
		t.Fatal("duplicate child accepted")
	}
}

func TestMetadata(t *testing.T) {
	e := newEnv(t)
	if e.md.EntityID != "https://idp.test/saml/metadata" || e.md.SSOURL != "https://idp.test/saml/sso" || len(e.md.Certs) != 1 {
		t.Fatalf("%+v", e.md)
	}
	good := string(e.idp.Metadata())
	bad := map[string]string{
		"not xml":         "nope",
		"wrong root":      `<a/>`,
		"no entity id":    strings.Replace(good, `entityID="https://idp.test/saml/metadata"`, ``, 1),
		"no idp":          strings.Replace(strings.Replace(good, "md:IDPSSODescriptor", "md:SPSSODescriptor", -1), "", "", 0),
		"not saml2":       strings.Replace(good, NSProtocol+`"`, `urn:other"`, 1),
		"no certificate":  strings.Replace(good, `use="signing"`, `use="encryption"`, 1),
		"bad certificate": strings.Replace(good, "<ds:X509Certificate>", "<ds:X509Certificate>AAAA", 1),
		"bad base64 cert": strings.Replace(good, "<ds:X509Certificate>", "<ds:X509Certificate>!", 1),
		"http sso":        strings.Replace(good, `Location="https://`, `Location="http://`, 1),
		"post-only sso":   strings.Replace(good, BindingRedirect, BindingPOST, 1),
	}
	for name, x := range bad {
		if _, err := ParseIdPMetadata([]byte(x)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	signed := strings.Replace(good, `<md:IDPSSODescriptor `, `<md:IDPSSODescriptor WantAuthnRequestsSigned="true" `, 1)
	md, err := ParseIdPMetadata([]byte(signed))
	if err != nil || !md.WantRequestsSigned {
		t.Fatal(err)
	}
	if _, err := New(Config{EntityID: spEntity, ACSURL: acsURL, IdP: md}); err == nil {
		t.Fatal("IdP wants signed requests; SP without key accepted")
	}

	out, err := e.sp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`entityID="` + spEntity + `"`, `Location="` + acsURL + `"`, `use="encryption"`, `use="signing"`,
		base64.StdEncoding.EncodeToString(spCert.Raw)[:40], EncAES256GCM} {
		if !strings.Contains(string(out), want) {
			t.Errorf("SP metadata lacks %q", want)
		}
	}
	plain, _ := e.newSP(func(c *Config) { c.Key, c.Cert = nil, nil }).Metadata()
	if strings.Contains(string(plain), "KeyDescriptor") {
		t.Error("key descriptor without a certificate")
	}
}

func TestAuthnRequestURL(t *testing.T) {
	e := newEnv(t)
	for _, sign := range []bool{false, true} {
		sp := e.newSP(func(c *Config) { c.SignRequests = sign; c.NameIDFormat = NameIDEmail })
		u, err := sp.AuthnRequestURL(reqID, "relay-1")
		if err != nil {
			t.Fatal(err)
		}
		pu, _ := url.Parse(u)
		q := pu.Query()
		raw, _ := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
		xmlBytes, _ := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(xmlBytes); err != nil {
			t.Fatal(err)
		}
		r := doc.Root()
		if r.SelectAttrValue("ID", "") != reqID || r.SelectAttrValue("AssertionConsumerServiceURL", "") != acsURL ||
			r.SelectAttrValue("Destination", "") != e.md.SSOURL || r.SelectAttrValue("ProtocolBinding", "") != BindingPOST ||
			find(r, "Issuer").Text() != spEntity || find(r, "NameIDPolicy").SelectAttrValue("Format", "") != NameIDEmail {
			t.Fatalf("request %s", xmlBytes)
		}
		if q.Get("RelayState") != "relay-1" || (q.Get("Signature") != "") != sign {
			t.Fatalf("query %v", q)
		}
		if sign {
			signed := pu.RawQuery[:strings.Index(pu.RawQuery, "&Signature=")]
			sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
			sum := sha256.Sum256([]byte(signed))
			if err := rsa.VerifyPKCS1v15(&spKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
				t.Fatal("redirect signature does not verify")
			}
		}
	}
	if _, err := e.sp.AuthnRequestURL(reqID, strings.Repeat("r", 81)); err == nil {
		t.Fatal("long RelayState accepted")
	}
	md := *e.md
	md.SSOURL = "https://idp.test/sso?tenant=1"
	sp := e.newSP(func(c *Config) { c.IdP = &md })
	if u, _ := sp.AuthnRequestURL(reqID, ""); !strings.Contains(u, "?tenant=1&SAMLRequest=") || strings.Contains(u, "RelayState") {
		t.Fatalf("existing query: %s", u)
	}
	if !strings.HasPrefix(NewRequestID(), "_") || len(NewRequestID()) != 33 {
		t.Fatal("request id")
	}
}

func TestNewValidation(t *testing.T) {
	e := newEnv(t)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, f := range map[string]func(c *Config){
		"no entity":        func(c *Config) { c.EntityID = "" },
		"no idp":           func(c *Config) { c.IdP = nil },
		"key without cert": func(c *Config) { c.Cert = nil },
		"small key":        func(c *Config) { c.Key = small },
		"sign without key": func(c *Config) { c.Key, c.Cert, c.SignRequests = nil, nil, true },
	} {
		cfg := Config{EntityID: spEntity, ACSURL: acsURL, IdP: e.md, Key: spKey, Cert: spCert}
		f(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	sp, err := New(Config{EntityID: spEntity, ACSURL: acsURL, IdP: e.md, ProviderID: "x"})
	if err != nil || sp.ID() != "x" {
		t.Fatal(err)
	}
}

func TestReplayCache(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	rc := NewReplayCache(2, c.now)
	if !rc.Claim("a", c.now().Add(time.Minute)) || rc.Claim("a", c.now().Add(time.Minute)) {
		t.Fatal("claim once")
	}
	rc.Claim("b", c.now().Add(time.Minute))
	if rc.Claim("c", c.now().Add(time.Minute)) {
		t.Fatal("full cache must fail closed")
	}
	c.add(2 * time.Minute)
	if !rc.Claim("c", c.now().Add(time.Minute)) || !rc.Claim("a", c.now().Add(time.Minute)) {
		t.Fatal("expired entries make room and may be reused")
	}
	if rc.Len() != 2 || NewReplayCache(0, nil).capacity != DefaultReplayCapacity {
		t.Fatal("len/defaults")
	}
}

// TestPropertyMutationsNeverChangeIdentity applies one random structural
// change to a validly signed response: delete, duplicate or move an element,
// or edit text or an attribute. The response may be rejected, but if it is
// accepted the identity must be exactly the one the IdP signed.
func TestPropertyMutationsNeverChangeIdentity(t *testing.T) {
	e := newEnv(t)
	r := mrand.New(mrand.NewPCG(11, 12))
	accepted := 0
	for i := 0; i < 250; i++ {
		o := respOpts{signAssertion: r.IntN(2) == 0}
		o.signResponse = !o.signAssertion || r.IntN(2) == 0
		doc := e.doc(o)
		var all []*etree.Element
		var walk func(el *etree.Element)
		walk = func(el *etree.Element) {
			all = append(all, el)
			for _, c := range el.ChildElements() {
				walk(c)
			}
		}
		walk(doc.Root())
		target := all[1+r.IntN(len(all)-1)]
		parent := target.Parent()
		switch r.IntN(5) {
		case 0:
			parent.RemoveChild(target)
		case 1:
			parent.InsertChildAt(target.Index(), target.Copy())
		case 2:
			dest := all[r.IntN(len(all))]
			if dest != target && !isAncestor(target, dest) {
				parent.RemoveChild(target)
				dest.AddChild(target)
			}
		case 3:
			if len(target.ChildElements()) == 0 {
				target.SetText("admin@partner.example")
			}
		case 4:
			if len(target.Attr) > 0 {
				target.Attr[r.IntN(len(target.Attr))].Value = "_mutated"
			}
		}
		res, err := e.newSP(nil).ParseResponse(encode(t, doc), reqID)
		if err != nil {
			continue
		}
		accepted++
		id := res.Identity
		if id.Subject != "carol@partner.example" || id.Email != "carol@partner.example" || strings.Join(id.Groups, ",") != "eng" {
			t.Fatalf("mutation of <%s> changed the identity: %+v", target.Tag, id)
		}
	}
	t.Logf("%d of 250 mutated responses were still accepted, all with the signed identity", accepted)
}

func isAncestor(a, b *etree.Element) bool {
	for p := b; p != nil; p = p.Parent() {
		if p == a {
			return true
		}
	}
	return false
}

func FuzzParseResponse(f *testing.F) {
	e := newEnv(f)
	b, _ := e.doc(respOpts{signAssertion: true}).WriteToBytes()
	f.Add(b)
	f.Add([]byte(`<samlp:Response xmlns:samlp="` + NSProtocol + `" Version="2.0"/>`))
	sp := e.newSP(nil)
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := sp.ParseResponse(base64.StdEncoding.EncodeToString(b), reqID)
		if err != nil {
			return
		}
		if res.Identity.Subject != "carol@partner.example" {
			t.Fatalf("fuzzed input accepted with identity %+v", res.Identity)
		}
	})
}

func FuzzParseMetadata(f *testing.F) {
	e := newEnv(f)
	f.Add(e.idp.Metadata())
	f.Fuzz(func(t *testing.T, b []byte) {
		md, err := ParseIdPMetadata(b)
		if err != nil {
			return
		}
		if len(md.Certs) == 0 || !strings.HasPrefix(md.SSOURL, "https://") {
			t.Fatalf("accepted %+v", md)
		}
	})
}

func BenchmarkParseResponse(b *testing.B) {
	e := newEnv(b)
	sp := e.newSP(func(c *Config) { c.Replay = NewReplayCache(1<<30, nil) })
	resp := encode(b, e.doc(respOpts{signAssertion: true}))
	for b.Loop() {
		// A fresh replay cache per iteration would dominate; reuse the
		// response by clearing the remembered ID.
		sp.cfg.Replay.mu.Lock()
		clear(sp.cfg.Replay.seen)
		sp.cfg.Replay.mu.Unlock()
		if _, err := sp.ParseResponse(resp, reqID); err != nil {
			b.Fatal(err)
		}
	}
}

// TestAssertionShape covers the remaining structural checks, each reached by
// a validly signed assertion that is wrong in one way.
func TestAssertionShape(t *testing.T) {
	remove := func(tag string) func(a *etree.Element) {
		return func(a *etree.Element) {
			el := find(a, tag)
			el.Parent().RemoveChild(el)
		}
	}
	setAttr := func(tag, k, v string) func(a *etree.Element) {
		return func(a *etree.Element) { find(a, tag).CreateAttr(k, v) }
	}
	cases := map[string]struct {
		hook   func(a *etree.Element)
		reason string
	}{
		"no Conditions":           {remove("Conditions"), ReasonMalformed},
		"no AudienceRestriction":  {remove("AudienceRestriction"), ReasonAudience},
		"no AuthnStatement":       {remove("AuthnStatement"), ReasonMalformed},
		"no Subject":              {remove("Subject"), ReasonSubject},
		"no NameID":               {remove("NameID"), ReasonSubject},
		"empty NameID":            {func(a *etree.Element) { find(a, "NameID").SetText("") }, ReasonSubject},
		"huge NameID":             {func(a *etree.Element) { find(a, "NameID").SetText(strings.Repeat("n", 600)) }, ReasonSubject},
		"no Issuer":               {remove("Issuer"), ReasonIssuer},
		"wrong version":           {func(a *etree.Element) { a.CreateAttr("Version", "1.1") }, ReasonMalformed},
		"holder-of-key only":      {setAttr("SubjectConfirmation", "Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"), ReasonSubject},
		"no confirmation data":    {remove("SubjectConfirmationData"), ReasonSubject},
		"no confirmation expiry":  {func(a *etree.Element) { find(a, "SubjectConfirmationData").RemoveAttr("NotOnOrAfter") }, ReasonSubject},
		"confirmation expired":    {setAttr("SubjectConfirmationData", "NotOnOrAfter", "2001-01-01T00:00:00Z"), ReasonExpired},
		"confirmation for a year": {setAttr("SubjectConfirmationData", "NotOnOrAfter", time.Now().AddDate(1, 0, 0).UTC().Format(timeFormat)), ReasonSubject},
		"bad confirmation time":   {setAttr("SubjectConfirmationData", "NotOnOrAfter", "tomorrow"), ReasonMalformed},
		"bad NotBefore":           {setAttr("Conditions", "NotBefore", "yesterday"), ReasonMalformed},
		"bad NotOnOrAfter":        {setAttr("Conditions", "NotOnOrAfter", "never"), ReasonMalformed},
		"bad SessionNotOnOrAfter": {setAttr("AuthnStatement", "SessionNotOnOrAfter", "x"), ReasonMalformed},
		"too many group values": {func(a *etree.Element) {
			g := find(a, "AttributeStatement").ChildElements()[2]
			for i := 0; i <= maxAttributeValues; i++ {
				g.CreateElement("saml:AttributeValue").SetText("g")
			}
		}, ReasonAttributes},
		"invalid group name": {func(a *etree.Element) {
			find(a, "AttributeStatement").ChildElements()[2].CreateElement("saml:AttributeValue").SetText(strings.Repeat("g", 300))
		}, ReasonAttributes},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			_, err := e.sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true, beforeSign: c.hook})), reqID)
			if got := reasonOf(err); got != c.reason {
				t.Fatalf("reason %q (%v), want %q", got, err, c.reason)
			}
		})
	}
	// Envelope checks on an unsigned Response around a signed assertion.
	e := newEnv(t)
	for name, f := range map[string]func(r *etree.Element){
		"response without ID": func(r *etree.Element) { r.RemoveAttr("ID") },
		"no Status":           func(r *etree.Element) { r.RemoveChild(directChild(r, "Status")) },
		"no StatusCode":       func(r *etree.Element) { s := directChild(r, "Status"); s.RemoveChild(directChild(s, "StatusCode")) },
		"wrong version":       func(r *etree.Element) { r.CreateAttr("Version", "1.0") },
	} {
		doc := e.doc(respOpts{signAssertion: true})
		f(doc.Root())
		if _, err := e.sp.ParseResponse(encode(t, doc), reqID); reasonOf(err) != ReasonMalformed {
			t.Errorf("%s: %v", name, err)
		}
	}
	err := &Error{Reason: "r", Err: errors.New("e")}
	if err.Error() != "saml: r: e" || errors.Unwrap(err) == nil || (&wrappingError{"w"}).Error() != "w" {
		t.Fatal("error types")
	}
	if first(nil) != "" || truncate("a\x00bcd", 2) != "ab" {
		t.Fatal("helpers")
	}
}

func TestFetchIdPMetadata(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(404)
			return
		}
		w.Write(e.idp.Metadata())
	}))
	defer srv.Close()
	ctx := context.Background()
	md, err := FetchIdPMetadata(ctx, srv.Client(), srv.URL+"/md")
	if err != nil || md.EntityID != e.md.EntityID {
		t.Fatal(err)
	}
	if _, err := FetchIdPMetadata(ctx, srv.Client(), srv.URL+"/missing"); err == nil {
		t.Fatal("404 accepted")
	}
	if _, err := FetchIdPMetadata(ctx, srv.Client(), "http://example.com/md"); err == nil {
		t.Fatal("http accepted")
	}
	if _, err := FetchIdPMetadata(ctx, http.DefaultClient, srv.URL+"/md"); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
