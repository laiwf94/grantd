package fakeidp

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	idp *IdP
	srv *httptest.Server
	c   *http.Client
}

func newFixture(t *testing.T, sps ...ServiceProvider) *fixture {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	iss := "http://" + srv.Listener.Addr().String()
	idp, err := New(Config{Issuer: iss, Clients: []Client{{ID: "app", Secret: "pw", RedirectURIs: []string{"https://app/cb"},
		PostLogoutRedirectURIs: []string{"https://app/bye"}}}, ServiceProviders: sps})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = idp
	srv.Start()
	t.Cleanup(srv.Close)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &fixture{idp: idp, srv: srv, c: c}
}

func (f *fixture) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := f.c.Get(f.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func (f *fixture) post(t *testing.T, path string, form url.Values, user, pass string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := f.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func goodAuthorize() url.Values {
	return url.Values{"client_id": {"app"}, "redirect_uri": {"https://app/cb"}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"s"}, "nonce": {"n"}, "code_challenge_method": {"S256"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}}
}

func TestOIDCFlowAndErrors(t *testing.T) {
	f := newFixture(t)
	if resp, body := f.get(t, "/.well-known/openid-configuration"); resp.StatusCode != 200 || !strings.Contains(body, `"S256"`) {
		t.Fatal("discovery")
	}
	if _, body := f.get(t, "/jwks"); !strings.Contains(body, KeyID) {
		t.Fatal("jwks")
	}
	// Bad authorization requests are shown, not redirected.
	for k, v := range map[string]string{"client_id": "ghost", "redirect_uri": "https://evil/cb", "response_type": "token",
		"code_challenge_method": "plain", "scope": "email", "nonce": ""} {
		q := goodAuthorize()
		q.Set(k, v)
		if resp, _ := f.get(t, "/authorize?"+q.Encode()); resp.StatusCode != 400 {
			t.Errorf("%s=%s: %d", k, v, resp.StatusCode)
		}
	}
	q := goodAuthorize()
	if resp, body := f.get(t, "/authorize?"+q.Encode()); resp.StatusCode != 200 || !strings.Contains(body, "Sign in") {
		t.Fatal("form")
	}
	q.Set("username", "alice")
	q.Set("password", "wrong")
	if resp, body := f.post(t, "/authorize", q, "", ""); resp.StatusCode != 401 || !strings.Contains(body, "Wrong username") {
		t.Fatal("wrong password")
	}
	q.Set("password", "alice-pass")
	resp, _ := f.post(t, "/authorize", q, "", "")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if resp.StatusCode != 302 || code == "" || loc.Query().Get("state") != "s" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app/cb"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	if resp, _ := f.post(t, "/token", tokenForm, "app", "wrong"); resp.StatusCode != 401 {
		t.Fatal("bad client secret")
	}
	bad := url.Values{}
	for k, v := range tokenForm {
		bad[k] = v
	}
	bad.Set("code_verifier", "wrong-verifier")
	if resp, body := f.post(t, "/token", bad, "app", "pw"); resp.StatusCode != 400 || !strings.Contains(body, "PKCE") {
		t.Fatalf("PKCE: %s", body)
	}
	// The failed attempt used the code up.
	if resp, _ := f.post(t, "/token", tokenForm, "app", "pw"); resp.StatusCode != 400 {
		t.Fatal("code reused")
	}
	// Fresh code, client_secret_post this time.
	resp, _ = f.post(t, "/authorize", q, "", "")
	loc, _ = url.Parse(resp.Header.Get("Location"))
	tokenForm.Set("code", loc.Query().Get("code"))
	tokenForm.Set("client_id", "app")
	tokenForm.Set("client_secret", "pw")
	resp, body := f.post(t, "/token", tokenForm, "", "")
	var tr map[string]any
	json.Unmarshal([]byte(body), &tr)
	if resp.StatusCode != 200 || tr["id_token"] == nil {
		t.Fatalf("token: %s", body)
	}
	at := tr["access_token"].(string)
	req, _ := http.NewRequest("GET", f.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	uresp, _ := f.c.Do(req)
	ub, _ := io.ReadAll(uresp.Body)
	if uresp.StatusCode != 200 || !strings.Contains(string(ub), "alice@example.org") {
		t.Fatal("userinfo")
	}
	req.Header.Set("Authorization", "Bearer nope")
	if uresp, _ := f.c.Do(req); uresp.StatusCode != 401 {
		t.Fatal("userinfo with a bad token")
	}
	for _, form := range []url.Values{{"grant_type": {"refresh_token"}}, {"grant_type": {"authorization_code"}, "code": {"x"}}} {
		if resp, _ := f.post(t, "/token", form, "app", "pw"); resp.StatusCode != 400 {
			t.Errorf("token form %v", form)
		}
	}
	if resp, _ := f.post(t, "/token", url.Values{}, "", ""); resp.StatusCode != 401 {
		t.Error("no client")
	}
	// End session.
	if resp, _ := f.get(t, "/logout?client_id=app&post_logout_redirect_uri=https://app/bye"); resp.StatusCode != 302 {
		t.Error("registered post-logout redirect")
	}
	if resp, _ := f.get(t, "/logout?client_id=app&post_logout_redirect_uri=https://evil/"); resp.StatusCode != 400 {
		t.Error("unregistered post-logout redirect")
	}
	if resp, _ := f.get(t, "/logout"); resp.StatusCode != 200 {
		t.Error("plain logout")
	}
	if resp, _ := f.get(t, "/healthz"); resp.StatusCode != 200 {
		t.Error("health")
	}
}

func samlRequest(t *testing.T, issuer, acs, dest string) string {
	x := `<samlp:AuthnRequest xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `" ID="_r1" Version="2.0" Destination="` + dest +
		`" AssertionConsumerServiceURL="` + acs + `"><saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(x))
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestSAMLErrors(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := SelfSignedCert(key, "sp", time.Now())
	f := newFixture(t, ServiceProvider{EntityID: "https://sp/md", ACSURL: "https://sp/acs", SignAssertion: true},
		ServiceProvider{EntityID: "https://signed-sp/md", ACSURL: "https://signed-sp/acs", RequestCert: cert})
	if resp, body := f.get(t, "/saml/metadata"); resp.StatusCode != 200 || !strings.Contains(body, "IDPSSODescriptor") {
		t.Fatal("metadata")
	}
	sso := f.srv.URL + "/saml/sso"
	cases := map[string]string{
		"not base64":   "SAMLRequest=!!",
		"not deflated": "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("plain"))),
		"unknown SP":   "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://ghost/md", "https://sp/acs", sso)),
		"wrong ACS":    "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://sp/md", "https://evil/acs", sso)),
		"wrong dest":   "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://sp/md", "https://sp/acs", "https://other/sso")),
		"unsigned to SP that requires signatures": "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://signed-sp/md", "https://signed-sp/acs", sso)),
		"bad signature": "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://signed-sp/md", "https://signed-sp/acs", sso)) +
			"&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") + "&Signature=AAAA",
		"bad signature b64": "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://signed-sp/md", "https://signed-sp/acs", sso)) +
			"&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") + "&Signature=!",
		"bad query": "%zz",
	}
	for name, q := range cases {
		if resp, _ := f.get(t, "/saml/sso?"+q); resp.StatusCode != 400 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	good := "SAMLRequest=" + url.QueryEscape(samlRequest(t, "https://sp/md", "https://sp/acs", sso)) + "&RelayState=rs"
	if resp, _ := f.get(t, "/saml/sso?"+good); resp.StatusCode != 200 {
		t.Fatal("form")
	}
	if resp, _ := f.post(t, "/saml/sso", url.Values{"query": {good}, "username": {"bob"}, "password": {"x"}}, "", ""); resp.StatusCode != 401 {
		t.Fatal("wrong password")
	}
	if resp, _ := f.post(t, "/saml/sso", url.Values{"query": {"SAMLRequest=!!"}}, "", ""); resp.StatusCode != 400 {
		t.Fatal("bad request on POST")
	}
	resp, body := f.post(t, "/saml/sso", url.Values{"query": {good}, "username": {"bob"}, "password": {"bob-pass"}}, "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `action="https://sp/acs"`) || !strings.Contains(body, `value="rs"`) {
		t.Fatalf("post form: %s", body)
	}
	if _, err := f.idp.SAMLResponse(ResponseOptions{SP: ServiceProvider{EncryptCert: f.idp.Certificate()}, User: DemoUsers[0]}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Issuer: "not a url"}); err == nil {
		t.Fatal("bad issuer")
	}
}
