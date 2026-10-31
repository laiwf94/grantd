package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/beevik/etree"
)

// XML namespaces and identifiers used by SAML 2.0.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	NSDSig      = "http://www.w3.org/2000/09/xmldsig#"
	NSXEnc      = "http://www.w3.org/2001/04/xmlenc#"
	NSXEnc11    = "http://www.w3.org/2009/xmlenc11#"

	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	MethodBearer    = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// Parser limits for untrusted XML.
const (
	MaxXMLBytes  = 256 << 10
	maxXMLDepth  = 48
	maxXMLTokens = 50_000
)

var idRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,255}$`)

// parseStrict parses untrusted XML after a token-level scan that rejects
// everything a SAML message has no use for and attacks rely on: DOCTYPE
// (entity expansion, external entities), comments (the NameID comment
// truncation trick, CVE-2017-11427 and relatives), processing instructions,
// deep nesting and huge token counts.
func parseStrict(b []byte) (*etree.Document, error) {
	if len(b) > MaxXMLBytes {
		return nil, fmt.Errorf("document larger than %d bytes", MaxXMLBytes)
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	depth, tokens, roots := 0, 0, 0
	for {
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid XML: %v", err)
		}
		if tokens++; tokens > maxXMLTokens {
			return nil, errors.New("too many XML tokens")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if roots++; roots > 1 {
					return nil, errors.New("more than one root element")
				}
			}
			if depth++; depth > maxXMLDepth {
				return nil, errors.New("XML nested too deeply")
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return nil, errors.New("DOCTYPE and other directives are not allowed")
		case xml.Comment:
			return nil, errors.New("comments are not allowed")
		case xml.ProcInst:
			if t.Target != "xml" || tokens != 1 {
				return nil, errors.New("processing instructions are not allowed")
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return nil, errors.New("text outside the root element")
			}
		}
	}
	if roots != 1 {
		return nil, errors.New("no root element")
	}
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = false
	if err := doc.ReadFromBytes(b); err != nil {
		return nil, fmt.Errorf("invalid XML: %v", err)
	}
	return doc, nil
}

// is reports whether el is {ns}tag.
func is(el *etree.Element, ns, tag string) bool {
	return el != nil && el.Tag == tag && el.NamespaceURI() == ns
}

// children returns the direct child elements {ns}tag.
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

// child returns the single direct child {ns}tag; more than one is an error.
func child(el *etree.Element, ns, tag string) (*etree.Element, error) {
	cs := children(el, ns, tag)
	switch len(cs) {
	case 0:
		return nil, nil
	case 1:
		return cs[0], nil
	}
	return nil, fmt.Errorf("more than one %s", tag)
}

// descendants counts {ns}tag elements anywhere under (and including) el.
func descendants(el *etree.Element, ns, tag string) int {
	n := 0
	if is(el, ns, tag) {
		n++
	}
	for _, c := range el.ChildElements() {
		n += descendants(c, ns, tag)
	}
	return n
}

// countID counts elements under (and including) el whose ID attribute is id.
func countID(el *etree.Element, id string) int {
	n := 0
	for _, a := range el.Attr {
		if a.Key == "ID" && a.Space == "" && a.Value == id {
			n++
		}
	}
	for _, c := range el.ChildElements() {
		n += countID(c, id)
	}
	return n
}

// text returns the character content of an element that must hold only
// text: any child element makes it an error, and split character data
// (text, CDATA, text) is joined so no part can be silently dropped.
func text(el *etree.Element) (string, error) {
	var b strings.Builder
	for _, tok := range el.Child {
		switch t := tok.(type) {
		case *etree.CharData:
			b.WriteString(t.Data)
		default:
			return "", fmt.Errorf("%s must contain only text", el.Tag)
		}
	}
	return strings.TrimSpace(b.String()), nil
}

func attr(el *etree.Element, name string) string {
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value
		}
	}
	return ""
}
