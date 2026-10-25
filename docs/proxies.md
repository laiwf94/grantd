# Proxy configuration

wicket answers one question for a reverse proxy: may this request through, and
as whom? The proxy sends it the original request's headers (cookies included,
no body) and acts on the status code:

| wicket answers | The proxy should |
|---|---|
| `200` with `X-Auth-*` headers | forward the request upstream, copying the `X-Auth-*` headers onto it |
| `401` with `X-Auth-Redirect: <login URL>` | send the browser to that URL (or return 401 to API clients) |
| `302` to the login URL (only with `?redirect=1`, or on the Envoy endpoint) | pass the redirect to the browser |
| `403` | refuse the request (wicket renders a "no access" page for browsers) |

Two rules apply to every proxy:

1. **Strip client-supplied `X-Auth-*` headers.** The identity headers are only
   trustworthy if the proxy removes or overwrites any copy the client sent.
   The snippets below do that. Apps that can verify the `X-Auth-Token` JWT
   against `/.well-known/jwks.json` should, because then a mistake in the
   proxy configuration can't turn into an impersonation.
2. **Route the browser-facing endpoints** (`/login`, `/callback/...`,
   `/saml/...`, `/logout`, `/logged-out`, `/.well-known/jwks.json`) to wicket
   under the `public_url` from its config. The examples use
   `https://app.example.com/_wicket`.

## nginx (`auth_request`)

`auth_request` only understands 2xx, 401 and 403, so wicket returns 401 with
the login URL in `X-Auth-Redirect` and nginx turns that into a redirect. The
demo (`examples/demo.sh`) runs exactly this configuration in Docker.

```nginx
location /_wicket/ {
  proxy_pass http://wicket:4180/;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

location = /_wicket/auth {
  internal;                                   # not reachable from outside
  proxy_pass http://wicket:4180/auth?app=myapp;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header X-Forwarded-Proto  $scheme;
  proxy_set_header X-Forwarded-Host   $http_host;
  proxy_set_header X-Forwarded-Uri    $request_uri;
  proxy_set_header X-Forwarded-Method $request_method;
}

location / {
  auth_request /_wicket/auth;
  auth_request_set $auth_user     $upstream_http_x_auth_user;
  auth_request_set $auth_email    $upstream_http_x_auth_email;
  auth_request_set $auth_groups   $upstream_http_x_auth_groups;
  auth_request_set $auth_token    $upstream_http_x_auth_token;
  auth_request_set $auth_redirect $upstream_http_x_auth_redirect;
  error_page 401 = @login;

  # Set unconditionally: an empty value removes the header, so a client's
  # own X-Auth-User never reaches the app.
  proxy_set_header X-Auth-User   $auth_user;
  proxy_set_header X-Auth-Email  $auth_email;
  proxy_set_header X-Auth-Groups $auth_groups;
  proxy_set_header X-Auth-Token  $auth_token;
  proxy_pass http://myapp:8080;
}

location @login {
  return 302 $auth_redirect;
}
```

## Traefik (`ForwardAuth`)

Traefik passes a non-2xx answer from the auth server straight to the client,
so wicket can redirect browsers itself (`?redirect=1`); API calls (no
`text/html` in `Accept`, `X-Requested-With` set, or a non-GET method) still
get a 401 JSON error. Traefik sets `X-Forwarded-Method/-Proto/-Host/-Uri`.

```yaml
http:
  middlewares:
    strip-identity:
      headers:
        customRequestHeaders:          # an empty value deletes the header
          X-Auth-User: ""
          X-Auth-Email: ""
          X-Auth-Groups: ""
          X-Auth-Provider: ""
          X-Auth-Token: ""
    wicket:
      forwardAuth:
        address: "http://wicket:4180/auth?redirect=1"
        trustForwardHeader: false
        authResponseHeaders: ["X-Auth-User", "X-Auth-Email", "X-Auth-Groups", "X-Auth-Provider", "X-Auth-Token"]
    wicket-prefix:
      stripPrefix:
        prefixes: ["/_wicket"]
  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      middlewares: ["strip-identity", "wicket"]
      service: myapp
    wicket:
      rule: "Host(`app.example.com`) && PathPrefix(`/_wicket`)"
      middlewares: ["wicket-prefix"]
      service: wicket
  services:
    myapp:
      loadBalancer: {servers: [{url: "http://myapp:8080"}]}
    wicket:
      loadBalancer: {servers: [{url: "http://wicket:4180"}]}
```

The app is found from `X-Forwarded-Host`, so one middleware serves every
host listed in wicket's config.

## Envoy (`ext_authz`, HTTP service)

Envoy appends the original path to `path_prefix` and keeps the original
`Host`, so the endpoint is `/auth/envoy/<original path>`. Denied answers
(including wicket's 302) go to the client.

```yaml
http_filters:
# Runs first, so a client's own identity headers are gone before ext_authz
# adds wicket's.
- name: envoy.filters.http.header_mutation
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation
    mutations:
      request_mutations:
      - remove: x-auth-user
      - remove: x-auth-email
      - remove: x-auth-groups
      - remove: x-auth-provider
      - remove: x-auth-token
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    http_service:
      server_uri: {uri: "wicket:4180", cluster: wicket, timeout: 2s}
      path_prefix: /auth/envoy
      authorization_request:
        allowed_headers:
          patterns: [{exact: cookie}, {exact: accept}, {exact: x-requested-with}, {exact: x-forwarded-proto}]
      authorization_response:
        allowed_upstream_headers:
          patterns: [{prefix: x-auth-}]
        allowed_client_headers:
          patterns: [{exact: location}, {exact: content-type}, {exact: x-auth-redirect}]
- name: envoy.filters.http.router
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

route_config:
  virtual_hosts:
  - name: app
    domains: ["app.example.com"]
    routes:
    - match: {prefix: "/_wicket/"}
      route: {cluster: wicket, prefix_rewrite: "/"}
      typed_per_filter_config:
        envoy.filters.http.ext_authz:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
          disabled: true
    - match: {prefix: "/"}
      route: {cluster: myapp}
```

Route-level `request_headers_to_remove` would not work here: the router
applies it after ext_authz, so it would delete wicket's headers too. Filters
run in order, which is why the stripping is a filter placed before ext_authz.

The nginx configuration is exercised live by the demo. The Traefik and Envoy
snippets follow those proxies' documented forward-auth behavior; wicket's side
of both (`?redirect=1` and `/auth/envoy/`) is covered by the end-to-end tests.
