// Package check validates a configuration file the way the gateway would
// load it, without starting it: the schema and semantic checks of the
// config package, then the files each provider names (CA bundles, SP keys
// and certificates, SAML metadata) and, when asked, whether each provider's
// metadata can be fetched and used. Every problem carries the JSON path of
// the setting it is about.
package check

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/wicket/internal/config"
	"github.com/laiwf94/wicket/internal/keyfile"
	"github.com/laiwf94/wicket/internal/oidc"
	"github.com/laiwf94/wicket/internal/saml"
)

// DefaultTimeout bounds the online checks of one provider.
const DefaultTimeout = 10 * time.Second

// expiringSoon is how far ahead certificate expiry is warned about.
const expiringSoon = 30 * 24 * time.Hour

// Options control a check.
type Options struct {
	// Getenv resolves client_secret_env; nil treats every variable as
	// empty.
	Getenv func(string) string
	// Online also fetches each provider's metadata (OpenID discovery and
	// signing keys, SAML metadata URLs). Without it nothing touches the
	// network.
	Online bool
	// Timeout bounds the online checks of each provider; 0 means
	// DefaultTimeout.
	Timeout time.Duration
	// Client builds the back-channel client for a provider from its CA
	// pool (nil for the system roots). Nil builds the gateway's own.
	Client func(p *config.Provider, roots *x509.CertPool) *http.Client
	// Now is the clock for certificate validity; nil is time.Now.
	Now func() time.Time
}

// File checks the configuration file at path.
func File(ctx context.Context, path string, o Options) *config.Result {
	b, err := config.ReadFile(path)
	if err != nil {
		return &config.Result{Problems: config.Problems{{Path: "$", Severity: config.SeverityError, Message: err.Error()}}}
	}
	return Bytes(ctx, b, o)
}

// Bytes checks a configuration document.
func Bytes(ctx context.Context, b []byte, o Options) *config.Result {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Client == nil {
		o.Client = defaultClient
	}
	r := config.Check(b, o.Getenv)
	if r.Config == nil {
		return r
	}
	var wg sync.WaitGroup
	for i := range r.Config.Providers {
		wg.Go(func() {
			c := &checker{r: r, o: o, cfg: r.Config, p: &r.Config.Providers[i], path: fmt.Sprintf("$.providers[%d]", i)}
			c.provider(ctx)
		})
	}
	wg.Wait()
	r.Sort()
	return r
}

func defaultClient(_ *config.Provider, roots *x509.CertPool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return oidc.NewHTTPClient(tr)
}

// checker checks one provider.
type checker struct {
	r    *config.Result
	o    Options
	cfg  *config.Config
	p    *config.Provider
	path string
}

func (c *checker) provider(ctx context.Context) {
	var roots *x509.CertPool
	if c.p.CAFile != "" {
		pool, certs, err := keyfile.CAPool(c.p.CAFile)
		if err != nil {
			c.r.Errorf(c.path+".ca_file", "%v", err)
			// Without the pool the provider's TLS server would be
			// checked against the wrong roots: skip online checks.
			c.o.Online = false
		} else {
			roots = pool
			c.validity(c.path+".ca_file", "CA certificate", certs, false)
		}
	}
	client := c.o.Client(c.p, roots)
	switch c.p.Type {
	case config.ProviderOIDC:
		c.oidc(ctx, client)
	case config.ProviderSAML:
		c.saml(ctx, client)
	}
}

func (c *checker) oidc(ctx context.Context, client *http.Client) {
	if c.cfg.Public == nil || c.p.Issuer == "" || c.p.ClientID == "" {
		return // already reported; the provider can't be built
	}
	op, err := oidc.New(oidc.Config{
		ID: c.p.ID, Issuer: c.p.Issuer, ClientID: c.p.ClientID, ClientSecret: c.p.ClientSecret,
		ClientAuth: c.p.ClientAuth, RedirectURL: c.cfg.PublicURL + "/callback/" + c.p.ID, Scopes: c.p.Scopes,
		Algorithms: c.p.Algorithms, UseUserinfo: c.p.Userinfo, HTTPClient: client, Now: c.o.Now,
	})
	if err != nil {
		// The config checks cover what New validates; anything left
		// is reported against the provider as a whole.
		if !c.hasErrors() {
			c.r.Errorf(c.path, "%v", err)
		}
		return
	}
	if !c.o.Online {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, c.o.Timeout)
	defer cancel()
	m, err := op.Probe(ctx)
	if err != nil {
		c.r.Errorf(c.path+".issuer", "%v", err)
		return
	}
	if c.p.PostLogoutRedirectURL != "" && m.EndSessionEndpoint == "" {
		c.r.Warnf(c.path+".post_logout_redirect_url", "the provider has no end_session_endpoint, so logout ends only the wicket session")
	}
}

func (c *checker) saml(ctx context.Context, client *http.Client) {
	key, cert := c.spKeyPair()
	var md *saml.IdPMetadata
	switch {
	case c.p.IdPMetadataFile != "":
		at := c.path + ".idp_metadata_file"
		b, err := os.ReadFile(c.p.IdPMetadataFile)
		if err != nil {
			c.r.Errorf(at, "%v", err)
			return
		}
		if md, err = saml.ParseIdPMetadata(b); err != nil {
			c.r.Errorf(at, "%s: %v", c.p.IdPMetadataFile, err)
			return
		}
		c.idpCerts(at, md)
	case c.p.IdPMetadataURL != "" && c.o.Online:
		at := c.path + ".idp_metadata_url"
		ctx, cancel := context.WithTimeout(ctx, c.o.Timeout)
		defer cancel()
		var err error
		if md, err = saml.FetchIdPMetadata(ctx, client, c.p.IdPMetadataURL); err != nil {
			c.r.Errorf(at, "%v", err)
			return
		}
		c.idpCerts(at, md)
	default:
		return // a metadata URL, checked only online
	}
	if md.WantRequestsSigned && !c.p.SignRequests {
		c.r.Errorf(c.path+".sign_requests", "the identity provider wants signed requests (WantAuthnRequestsSigned); set sign_requests with sp_key_file and sp_cert_file")
		return
	}
	if c.hasErrors() || c.cfg.Public == nil {
		return
	}
	entityID := c.p.EntityID
	if entityID == "" {
		entityID = c.cfg.PublicURL + "/saml/" + c.p.ID + "/metadata"
	}
	if _, err := saml.New(saml.Config{ProviderID: c.p.ID, EntityID: entityID, ACSURL: c.cfg.PublicURL + "/saml/" + c.p.ID + "/acs",
		IdP: md, Key: key, Cert: cert, SignRequests: c.p.SignRequests, NameIDFormat: c.p.NameIDFormat, Now: c.o.Now}); err != nil {
		c.r.Errorf(c.path, "%v", err)
	}
}

// spKeyPair reads the SP key and certificate, reporting each file's
// problems at its own setting.
func (c *checker) spKeyPair() (key *rsa.PrivateKey, cert *x509.Certificate) {
	if c.p.SPKeyFile == "" || c.p.SPCertFile == "" {
		return nil, nil
	}
	k, kerr := keyfile.RSAKey(c.p.SPKeyFile)
	if kerr != nil {
		c.r.Errorf(c.path+".sp_key_file", "%v", kerr)
	}
	crt, cerr := keyfile.Certificate(c.p.SPCertFile)
	if cerr != nil {
		c.r.Errorf(c.path+".sp_cert_file", "%v", cerr)
	}
	if kerr != nil || cerr != nil {
		return nil, nil
	}
	if !k.PublicKey.Equal(crt.PublicKey) {
		c.r.Errorf(c.path+".sp_cert_file", "%s is not the certificate for %s", c.p.SPCertFile, c.p.SPKeyFile)
		return nil, nil
	}
	c.validity(c.path+".sp_cert_file", "SP certificate", []*x509.Certificate{crt}, false)
	return k, crt
}

// idpCerts reports expired IdP signing certificates: an error when none
// is valid, since every response would then be rejected.
func (c *checker) idpCerts(at string, md *saml.IdPMetadata) {
	c.validity(at, "IdP signing certificate", md.Certs, true)
}

func (c *checker) validity(at, what string, certs []*x509.Certificate, needOne bool) {
	now := c.o.Now()
	valid := 0
	var expired []string
	for _, crt := range certs {
		name := certName(crt)
		switch {
		case now.After(crt.NotAfter):
			expired = append(expired, fmt.Sprintf("%s expired %s", name, crt.NotAfter.UTC().Format(time.DateOnly)))
		case now.Before(crt.NotBefore):
			expired = append(expired, fmt.Sprintf("%s is not valid until %s", name, crt.NotBefore.UTC().Format(time.DateOnly)))
		default:
			valid++
			if crt.NotAfter.Sub(now) < expiringSoon {
				c.r.Warnf(at, "%s %s expires %s", what, name, crt.NotAfter.UTC().Format(time.DateOnly))
			}
		}
	}
	if len(expired) == 0 {
		return
	}
	msg := fmt.Sprintf("%s: %s", what, strings.Join(expired, "; "))
	if needOne && valid == 0 {
		c.r.Errorf(at, "%s (no valid certificate left)", msg)
		return
	}
	c.r.Warnf(at, "%s", msg)
}

func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return fmt.Sprintf("%q", c.Subject.CommonName)
	}
	return "serial " + c.SerialNumber.String()
}

// hasErrors reports whether this provider already has an error.
func (c *checker) hasErrors() bool {
	for _, p := range c.r.Snapshot() {
		if p.Severity == config.SeverityError && (p.Path == c.path || strings.HasPrefix(p.Path, c.path+".")) {
			return true
		}
	}
	return false
}
