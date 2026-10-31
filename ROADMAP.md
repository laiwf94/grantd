# wicket roadmap, November 2026 to October 2027

## Vision

By October 2027 wicket grows from an OpenID Connect and SAML forward-auth gateway into a full sign-in broker and identity provider with feature parity, for self-hosted workforce and customer identity, with Okta, Auth0, Microsoft Entra ID and Ping Identity among commercial services and Keycloak, Authentik, Ory, Zitadel and FusionAuth among open source ones: its own OpenID Connect and SAML provider, a user directory, passkeys and MFA, configurable authentication flows with risk signals, social, LDAP and enterprise federation, SCIM 2.0 in and out, organizations and tenants, an admin console with RBAC, API protection with client credentials, token exchange, device grant, DPoP and FAPI 2.0, an embedded Raft-replicated store for high availability, audit streaming, migrations from the leaders, SDKs and a Kubernetes path. It keeps oauth2-proxy's place in front of any app and keeps its edge where a small Go codebase wins: one static binary and an image under 25 MB, cold start under 100 ms, under 64 MB resident for 100,000 sessions, and forward-auth p99 under 1 ms, measured against Keycloak, Authentik, Zitadel and oauth2-proxy in a published benchmark that is re-run every quarter and enforced as a CI gate.

## Benchmarks

wicket is compared with Okta, Auth0, Microsoft Entra ID, Ping Identity, Keycloak, Authentik, Ory, Zitadel, FusionAuth and oauth2-proxy in the comparison. The footprint benchmark runs against the self-hostable ones (Keycloak, Authentik, Zitadel, Ory and oauth2-proxy). It lands in week 9 with explicit targets: image under 25 MB, cold start under 100 ms, RSS under 64 MB with 100,000 sessions, forward-auth p99 under 1 ms at 50,000 decisions/s on one core group, token endpoint at least 5,000 issuances/s per core. It is re-run in weeks 22, 35, 44 and 52, and a CI gate fails any change that regresses p99, throughput or RSS by more than 5%.

## 2026-11 · Interop, access rules, session lifecycle, observability, replicas

The first five v1 themes at one week each: releases and interop tests against real identity providers, path and claim rules with step-up, session revalidation and single logout, observability, and shared state for replicas.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 1 | 2026-11-02 to 2026-11-08 | Releases, config checks and interop with real identity providers | wicket is only tested against its own fakeidp, configs fail only at startup, and there are no release artifacts. This week delivers the v1 release and interop month: a config checker, signed releases, max_age handling and interop suites against Keycloak and SimpleSAMLphp. Closes comparison matrix rows D14, A1, A2. |
| 2 | 2026-11-09 to 2026-11-15 | Path, method and claim rules with step-up and explain | Access is per app by email, domain or group only. This week delivers the v1 access rules month: public paths, per-path rules, arbitrary claim matching, step-up and an explain API. Closes comparison matrix rows C2, B5. |
| 3 | 2026-11-16 to 2026-11-22 | Session lifecycle: revalidation, back-channel logout and SAML SLO | Sessions do not follow the identity provider: a disabled user keeps access until the session expires, and SAML logout is local only. This week delivers the v1 session lifecycle month. Closes comparison matrix rows A12, C8. |
| 4 | 2026-11-23 to 2026-11-29 | Observability: tracing, audit sinks, readiness and dashboards | Operators cannot follow a login across proxy, wicket and provider, audit lines go only to stdout, and readiness ignores provider health. This is the year's one observability week, delivering the v1 observability month. Closes comparison matrix rows D13, D5. |
| 5 | 2026-11-30 to 2026-12-06 | Shared state for replicas | One replica is a single point of failure, and running more needs a shared session store, replay caches and rate limits. This week delivers the v1 replicas month. Closes comparison matrix rows D7. |

## 2026-12 · Keys, API protection, provider breadth and the leader benchmark

Automated key rotation and Kubernetes deployment, bearer, DPoP and mTLS protection for APIs, private_key_jwt and PAR towards providers, and the first published footprint benchmark against Keycloak, Authentik, Zitadel and oauth2-proxy.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 6 | 2026-12-07 to 2026-12-13 | Key rotation, graceful drain and Kubernetes deployment | Signing and cookie keys rotate by hand and restarts drop requests. This week delivers the v1 keys and deployment month and is the year's one packaging week. Closes comparison matrix rows D11, D9. |
| 7 | 2026-12-14 to 2026-12-20 | Protecting APIs: bearer tokens, introspection, DPoP and mTLS | Non-browser clients cannot pass forward-auth today. This week delivers the v1 API protection month. Closes comparison matrix rows A8, A10. |
| 8 | 2026-12-21 to 2026-12-27 | Provider breadth: private_key_jwt, PAR, multi-tenant issuers, metadata refresh | Many enterprise providers need client authentication without shared secrets, pushed requests, multi-tenant issuer handling and fresh SAML metadata. This week delivers the v1 provider breadth month. Closes comparison matrix rows A11. |
| 9 | 2026-12-28 to 2027-01-03 | Performance at scale and the leader footprint benchmark | The README benchmarks are micro-benchmarks. This week delivers the v1 performance month and turns it into the first published benchmark against Keycloak, Authentik, Zitadel, Ory and oauth2-proxy, with a CI gate. Closes comparison matrix rows E1, E2, E3, E4. |

## 2027-01 · Hardening, operator experience, 1.0 and an identity store

Whole-handler fuzzing and supply chain checks, a first console with branded pages, the 1.0 gateway release, and the embedded transactional store every later identity feature builds on.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 10 | 2027-01-04 to 2027-01-10 | Hardening: whole-handler fuzzing, smuggling defences, supply chain, soak | Parsers are fuzzed but whole handlers are not, header ambiguity between proxy and gateway is an open risk, and nothing has run for days. This week delivers the v1 hardening month and is the year's one CI week. Closes comparison matrix rows D14. |
| 11 | 2027-01-11 to 2027-01-17 | Operator experience: console, config diffs, branded and accessible pages | Operators read JSON and logs to see what wicket is doing, and users see plain English pages. This week delivers the v1 operator experience month as the first, read-only console and polished hosted pages. Closes comparison matrix rows D2, D6. |
| 12 | 2027-01-18 to 2027-01-24 | Ecosystem and wicket 1.0 | The gateway needs to fit more proxies, give upstreams a library to verify its tokens and commit to a stable config before new identity features arrive. This week delivers the v1 ecosystem month and the 1.0 gateway release. Closes comparison matrix rows C1, D10. |
| 13 | 2027-01-25 to 2027-01-31 | Embedded transactional identity store | Every product in the matrix keeps users, clients, credentials and organizations in a durable store; wicket keeps only sessions in a log. An embedded transactional store with typed tables, secondary indexes and snapshots is the base for every identity feature that follows, and keeps the single-binary deployment. Closes comparison matrix rows D17. |

## 2027-02 · PostgreSQL, organizations, users and account flows

A PostgreSQL backend, multi-tenant organizations from the start, a user directory with password policy, and registration, verification and recovery flows.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 14 | 2027-02-01 to 2027-02-07 | PostgreSQL backend | Keycloak, Zitadel, Authentik and FusionAuth all run on PostgreSQL, and enterprises want identity data in a database they already back up and operate. A PostgreSQL implementation of the store interface gives that option without giving up the embedded default. New dependency: github.com/jackc/pgx/v5 through database/sql, because a correct PostgreSQL wire protocol client with TLS, SCRAM and prepared statements is far more than a week and pgx is the maintained standard. Closes comparison matrix rows D17, D7. |
| 15 | 2027-02-08 to 2027-02-14 | Organizations and multi-tenancy | Auth0 Organizations, Zitadel instances and organizations, FusionAuth tenants and Keycloak organizations let one deployment serve many customers or business units. Tenancy is built before users and clients exist so every row, key and route carries it. Closes comparison matrix rows D1. |
| 16 | 2027-02-15 to 2027-02-21 | User directory with password policy | wicket has no users of its own, so it cannot replace Keycloak, Zitadel, FusionAuth or the hosted services for anyone without an upstream identity provider. A user directory with groups, attributes and modern password handling is the base of every login method. New dependency: golang.org/x/crypto for argon2id, the OWASP-recommended password hash that the standard library does not provide. Closes comparison matrix rows B1. |
| 17 | 2027-02-22 to 2027-02-28 | Registration, verification and account recovery | Customer identity products (Auth0, FusionAuth, Ory Kratos, Zitadel) cover sign-up, email verification, password reset, magic links and invitations. Without them a directory needs an operator for every change. Closes comparison matrix rows B2. |

## 2027-03 · wicket as an identity provider, passkeys, MFA and flows

An OpenID Connect provider with refresh rotation and conformance tests, passkeys, MFA factors, and a configurable authentication flow engine.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 18 | 2027-03-01 to 2027-03-07 | OpenID Connect provider | Every identity provider in the matrix issues tokens to applications; wicket only consumes them. An OpenID Connect provider lets apps integrate directly instead of only through forward-auth. Closes comparison matrix rows A3. |
| 19 | 2027-03-08 to 2027-03-14 | Provider sessions, refresh rotation and OpenID conformance | A provider needs refresh tokens, consent, logout and certification before anyone trusts it. Hydra, Keycloak and Zitadel are OpenID certified; wicket should pass the same suite. Closes comparison matrix rows A3, A12. |
| 20 | 2027-03-15 to 2027-03-21 | Passkeys and WebAuthn | Passkeys are table stakes in the matrix (Okta, Auth0, Entra ID, Keycloak, Zitadel, FusionAuth, Kratos). WebAuthn registration and authentication on the standard library, with CBOR and COSE parsing written for it, gives phishing-resistant login. Closes comparison matrix rows B3. |
| 21 | 2027-03-22 to 2027-03-28 | Multi-factor authentication | Every leader offers TOTP, email or SMS codes and recovery codes; Okta, Entra and Auth0 add push. wicket needs a factor framework with enrollment and policy to protect password and federated logins. Closes comparison matrix rows B4. |
| 22 | 2027-03-29 to 2027-04-04 | Authentication flow engine and second-quarter benchmark | Keycloak flows, Authentik flows and stages, Ping DaVinci and Auth0 Actions let teams compose login steps without forking code. A flow engine turns wicket's fixed login into configurable steps, and the quarter closes with a benchmark re-run. Closes comparison matrix rows B6, E4. |

## 2027-04 · Risk signals, SAML IdP, brokering and directories

Risk-based authentication and breach detection, a SAML identity provider, social and enterprise brokering with account linking, and LDAP and Active Directory federation.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 23 | 2027-04-05 to 2027-04-11 | Risk signals, bot defence and device posture | Okta ThreatInsight, Entra ID Protection, Auth0 attack protection and Authentik device signals block attacks before a password is checked. wicket needs risk signals feeding the flow engine. Closes comparison matrix rows B7. |
| 24 | 2027-04-12 to 2027-04-18 | SAML identity provider | Enterprises still connect most SaaS apps through SAML, and every commercial and open source identity provider in the matrix except Ory's open source stack issues SAML assertions. wicket already has hardened SAML parsing and signing; this week turns it around into an IdP. Closes comparison matrix rows A4. |
| 25 | 2027-04-19 to 2027-04-25 | Identity brokering, social login and home realm discovery | Leaders broker logins to social and enterprise providers, link the identities to one user and route users to the right provider by email domain. wicket can talk to OIDC and SAML providers but keeps no user behind them. Closes comparison matrix rows A5, A7. |
| 26 | 2027-04-26 to 2027-05-02 | LDAP and Active Directory federation | Keycloak, Okta, Entra ID, Ping, Authentik, Zitadel and FusionAuth connect to existing LDAP and Active Directory, where most workforce identities still live. An LDAP v3 client written on the standard library brings that to wicket without a new dependency. Closes comparison matrix rows A6. |

## 2027-05 · Claims, provisioning, events and key management

Claims mapping, SCIM 2.0 server and outbound provisioning with lifecycle workflows, an audit event stream with webhooks, and envelope encryption with per-tenant keys.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 27 | 2027-05-03 to 2027-05-09 | Claims mapping, header mutators and login actions | Auth0 Actions, Zitadel Actions, Okta inline hooks and Oathkeeper mutators let teams shape tokens, assertions and upstream headers and call out at login. wicket's output is fixed today. Closes comparison matrix rows C4, B6. |
| 28 | 2027-05-10 to 2027-05-16 | SCIM 2.0 server | Okta, Entra ID and Auth0 push users and groups by SCIM, and Zitadel, Authentik and FusionAuth accept it. A SCIM server lets an upstream directory drive wicket's users and end their access at once. Closes comparison matrix rows C5. |
| 29 | 2027-05-17 to 2027-05-23 | Outbound provisioning and lifecycle workflows | Entra ID, Okta and Authentik provision users out to downstream apps and run joiner, mover and leaver steps. wicket needs the outbound side so apps behind it get accounts created and removed automatically. Closes comparison matrix rows C6. |
| 30 | 2027-05-24 to 2027-05-30 | Audit event stream and webhooks | Okta System Log and event hooks, Auth0 log streams, Keycloak event listeners and Zitadel's event-sourced audit make every identity event queryable and streamable. wicket writes audit lines only. Closes comparison matrix rows D5. |
| 31 | 2027-05-31 to 2027-06-06 | Encryption at rest and tenant key management | Hosted leaders encrypt customer data at rest and offer customer-managed keys at higher tiers. wicket stores secrets, credentials and personal data and needs envelope encryption with per-tenant keys. Closes comparison matrix rows D9. |

## 2027-06 · Admin RBAC, admin API and the admin console

Delegated admin roles, a complete admin API with a Terraform provider, and a console for people, apps, providers, flows and audit.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 32 | 2027-06-07 to 2027-06-13 | Admin RBAC, delegated administration and privileged access | Entra ID roles with PIM, Okta admin roles and Zitadel managers let organizations split admin power. wicket has one admin token. Closes comparison matrix rows D3. |
| 33 | 2027-06-14 to 2027-06-20 | Complete admin API and a Terraform provider | Every leader is managed as code: Okta, Auth0, Entra ID, Keycloak, Authentik, Zitadel and FusionAuth all have Terraform providers. wicket needs a complete admin API and a provider so tenants, apps and flows live in version control. New dependency, confined to a separate module terraform-provider-wicket: HashiCorp's terraform-plugin-framework, which is the only supported way to build a provider. Closes comparison matrix rows D4. |
| 34 | 2027-06-21 to 2027-06-27 | Admin console: people, sessions and organizations | Every product in the matrix except oauth2-proxy and Ory's open source stack has an admin console, and help desks will not use an API. The console grows from week 11's read-only pages into full user administration. Closes comparison matrix rows D2, C8. |
| 35 | 2027-06-28 to 2027-07-04 | Admin console: apps, providers, flows, audit and the second-quarter benchmark | Configuring apps, providers and flows is where admins spend time in Keycloak, Authentik and the hosted leaders. This week adds those editors and audit search, and re-runs the quarterly benchmark. Closes comparison matrix rows D2, E4. |

## 2027-07 · Custom domains and API identity

Custom domains with ACME, OAuth for services (client credentials, token exchange, JWT access tokens), device and native app grants, and FAPI 2.0.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 36 | 2027-07-05 to 2027-07-11 | Custom domains, certificates and branded email | Auth0, Okta, FusionAuth and Zitadel let each tenant use its own login domain and branded emails. wicket needs custom domains with automatic certificates, so an ACME client (RFC 8555) is written on the standard library. Closes comparison matrix rows D6. |
| 37 | 2027-07-12 to 2027-07-18 | OAuth for services: client credentials, token exchange and JWT access tokens | Machine-to-machine access is core to Okta, Auth0, Entra ID, Keycloak, Zitadel and Hydra. wicket as a provider must issue tokens to services, exchange them across service hops and let resource servers check them. Closes comparison matrix rows A8. |
| 38 | 2027-07-19 to 2027-07-25 | Device grant, native apps and back-channel authentication | TVs, CLIs and kiosks need the device grant, native apps need loopback redirects, and call centres and payment approvals use client-initiated back-channel authentication (CIBA). Keycloak, Okta, Auth0, Entra ID and Zitadel support these. Closes comparison matrix rows A9. |
| 39 | 2027-07-26 to 2027-08-01 | FAPI 2.0 security profile and conformance | Keycloak, Ping and Auth0 pass FAPI conformance and regulated industries (open banking, health) require it. wicket must pass the FAPI 2.0 Security Profile and Message Signing plans as a provider. Closes comparison matrix rows A11, A10. |

## 2027-08 · Authorization, HA, recovery, migration and performance

An authorization decision API, an embedded Raft-replicated store, backups and disaster recovery, migration from the leaders, and token path performance.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 40 | 2027-08-02 to 2027-08-08 | Authorization decision API | Okta FGA, Keycloak Authorization Services, PingAuthorize and Ory Keto let apps ask fine-grained questions beyond who is signed in. wicket's policy engine answers only at the gateway; exposing it as an OpenID AuthZEN evaluation API with resource attributes makes it usable from inside apps. Closes comparison matrix rows C3. |
| 41 | 2027-08-09 to 2027-08-15 | High availability on an embedded Raft-replicated store | Keycloak clusters on Infinispan, Zitadel and Authentik lean on PostgreSQL. Replicating wicket's embedded store with Raft gives three-node high availability from one binary with no database to run, a footprint none of the self-hosted leaders offer. Closes comparison matrix rows D7. |
| 42 | 2027-08-16 to 2027-08-22 | Backups, disaster recovery and multi-site | Keycloak documents multi-site deployments and the hosted leaders advertise regional resilience. wicket needs online backups, point-in-time restore and a standby site. Closes comparison matrix rows D8. |
| 43 | 2027-08-23 to 2027-08-29 | Migration from Keycloak, Auth0, Okta and other providers | Adoption depends on moving users without password resets. Auth0, FusionAuth and Ory import password hashes; wicket needs importers for the leaders and lazy migration for the rest. Closes comparison matrix rows D12. |
| 44 | 2027-08-30 to 2027-09-05 | Token path performance and the third-quarter benchmark | Keycloak publishes 15 password logins/s and 120 client credentials grants/s per vCPU, and Ory publishes about 513 grants/s on 2 vCPU. Beating these by a wide margin is a headline for wicket. This week tunes logins, token issuance and introspection and re-runs the quarterly benchmark. Closes comparison matrix rows E4. |

## 2027-09 · Footprint, upgrades, governance and device-bound sessions

Memory and cold start budgets, zero-downtime upgrades, access reviews and privacy tools, and device-bound session credentials.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 45 | 2027-09-06 to 2027-09-12 | Lower memory and faster cold start | Keycloak's sizing starts at about 1,250 MB per pod, Zitadel at about 512 MB and Authentik at 2 GB plus PostgreSQL. A small footprint is wicket's clearest win, and this week turns it into enforced budgets. Closes comparison matrix rows E1, E2, E3. |
| 46 | 2027-09-13 to 2027-09-19 | Zero-downtime upgrades and schema migrations | Identity is on the critical path of every app, so upgrades cannot cause downtime. Keycloak and Zitadel document rolling upgrades; wicket needs the same with both store backends. Closes comparison matrix rows D16. |
| 47 | 2027-09-20 to 2027-09-26 | Access reviews and privacy operations | Okta Identity Governance and Entra ID access reviews let auditors certify who can reach what; privacy law needs data export and erasure. wicket needs both to pass enterprise audits. Closes comparison matrix rows C7, D14. |
| 48 | 2027-09-27 to 2027-10-03 | Device-bound sessions | Okta Device-Bound SSO and Entra token protection bind sessions to a device key so stolen cookies are useless. Device Bound Session Credentials (DBSC) bring this to browsers; wicket can be among the first self-hosted gateways to support it. Closes comparison matrix rows B8. |

## 2027-10 · SDKs, Kubernetes integration, edge outposts and 2.0

SDKs in four languages, a Kubernetes controller and Gateway API integration, lightweight edge outposts, and wicket 2.0 with the final benchmark.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 49 | 2027-10-04 to 2027-10-10 | SDKs in Go, TypeScript, Python and Java | Auth0 ships SDKs in more than 30 languages and every leader has at least a few. wicket needs SDKs for apps to verify its tokens and DPoP proofs and for automation to drive its admin API, all without third-party dependencies. Closes comparison matrix rows D10. |
| 50 | 2027-10-11 to 2027-10-17 | Kubernetes controller and Gateway API integration | Teams on Kubernetes want identity configured next to their workloads, the way Keycloak's operator and Authentik's outposts integrate. A controller that turns custom resources into wicket objects and wires Gateway API external authorization makes wicket native there; the Helm packaging itself landed in week 6. Closes comparison matrix rows D11. |
| 51 | 2027-10-18 to 2027-10-24 | Edge outposts | Authentik outposts and Ory Oathkeeper run close to apps while a central server holds identity. A lightweight wicket outpost that answers forward-auth from a replicated, signed cache cuts latency for remote sites and keeps serving through a central outage. Closes comparison matrix rows D15. |
| 52 | 2027-10-25 to 2027-10-31 | wicket 2.0 and the final benchmark | The year ends with a supported identity provider release that 1.x gateway users can upgrade to in place, a final benchmark against the self-hostable leaders and the comparison matrix updated to what shipped. Closes comparison matrix rows E1, E2, E3, E4. |

## Next year

Gaps from the comparison matrix that stay open after October 2027:

- A first-party push authenticator app (row B4).
- Browser-based remote access and LDAP or RADIUS front-ends for legacy apps, as in Authentik (rows C1, D15).
- A catalogue of thousands of preconfigured app integrations, as in the Okta Integration Network.
- Continuous session risk through the OpenID Shared Signals Framework (row B7).
- Verifiable credentials with OpenID4VP and OpenID4VCI.
- Certified SOC 2, ISO 27001 or FedRAMP reports, which belong to whoever hosts wicket (row D14).
