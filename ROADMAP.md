# grantd: roadmap, November 2026 to October 2027

## Vision

By October 2027 grantd is an enterprise authorization platform at parity with Okta FGA, AuthZed SpiceDB and OpenFGA on the rows that matter: relationships with caveats, expiry and attribute policies, every query (check, bulk, lookups, expand, explain, watch), consistency tokens, a disk store and PostgreSQL, MySQL and CockroachDB backends, a Raft-replicated and sharded cluster with distributed dispatch and a materialized group index, tenants, SSO and RBAC for admins, audit and decision logs, encryption at rest, a console, a playground, a language server, SDKs in Go, TypeScript, Python and Java, drop-in APIs for SpiceDB and OpenFGA clients with migration tools, SCIM sync and a Kubernetes operator. It wins where a small Go binary can: no runtime dependencies, an image under 20 MB, cold start under 100 ms, the lowest memory per million relationships in the category and check p99 under 5 ms at 100 million relationships on one node, published in a reproducible benchmark against SpiceDB and OpenFGA, re-measured every quarter and held by a CI regression gate.

## Benchmarked against

Feature parity is measured against Okta FGA (Auth0 FGA), AuthZed (SpiceDB and AuthZed Dedicated), OpenFGA, Permit.io, Cerbos and Cerbos Hub, Oso Cloud, OPA (Styra DAS and Enterprise OPA are now end of life) and Topaz (community only since Aserto closed).Performance is measured against SpiceDB and OpenFGA in bench/, first in week 5 and then every quarter (weeks 22, 35, 48 and 52), with a CI gate on grantd's own numbers. Neither competitor publishes memory figures, so grantd publishes them.

Weeks 1 to 12 each deliver one whole monthly theme of the earlier draft; weeks 13 to 52 add the enterprise capabilities that close the gaps ranked in the comparison.

## 2026-11 · Complete API, conditions, schema tools and first benchmark

Weeks 1 to 5 deliver v1's first five monthly themes, one per week: explain, expand and the missing queries; group commit; expiring and caveated relationships; grantctl with schema tests; and reverse lookups with the first benchmark against SpiceDB and OpenFGA.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 1 | 2026-11-02 to 2026-11-08 | Explainable checks and the missing queries: explain, expand, lookup subjects, delete by filter, schema dry run | v1 month 1 in one week: SpiceDB and OpenFGA both offer expand, lookup subjects and debug traces, and operators cannot trust answers they cannot explain (matrix: APIs > expand, lookup subjects, explain, delete by filter). |
| 2 | 2026-11-09 to 2026-11-15 | Write path throughput: group commit, online checkpoints, idempotent retries, backpressure | v1 month 2 in one week: fsync per write caps throughput at the disk's sync rate (matrix: Scale > write throughput). |
| 3 | 2026-11-16 to 2026-11-22 | Expiring and conditional access: expiry, a CEL-subset caveat language, conditional results | v1 month 3 in one week: SpiceDB caveats, OpenFGA and Okta FGA conditions and SpiceDB expiry are table stakes (matrix: Modelling > caveats and conditions, expiring relationships). |
| 4 | 2026-11-23 to 2026-11-29 | Tooling for schema authors: grantctl, schema test files, backup and restore, schema diff | v1 month 4 in one week: every competitor ships a CLI and validation files for CI (matrix: Tooling > CLI, schema tests, migrations). |
| 5 | 2026-11-30 to 2026-12-06 | Lookups at scale and the first benchmark against SpiceDB and OpenFGA | v1 month 5 plus the early benchmark: scan-based lookups do not scale, and every later claim needs a fair comparison (matrix: APIs > lookup resources; Performance). |

## 2026-12 · Disk storage, replicas, tenants and observability

Weeks 6 to 9: a disk-backed segment store, log-shipping read replicas, scoped keys with tenants and audit, and the year's one observability week.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 6 | 2026-12-07 to 2026-12-13 | Storage beyond memory: interface, sorted segments, disk store, compaction | v1 month 6 in one week: the in-memory store caps data at RAM, the main doubt about grantd (matrix: Storage > disk-backed store). |
| 7 | 2026-12-14 to 2026-12-20 | Read replicas: replication stream, followers, token-aware reads, lag, fenced promotion | v1 month 7 in one week: SpiceDB and OpenFGA read from replicas; one node is a single point of failure (matrix: Scale > read replicas). |
| 8 | 2026-12-21 to 2026-12-27 | Scoped keys, tenants, rate limits and a tamper-evident audit log | v1 month 8 in one week: OpenFGA stores, Okta FGA audit logs and least-privilege keys are expected by any shared service (matrix: Management > multi-tenancy, audit logs; Security > scoped keys). |
| 9 | 2026-12-28 to 2027-01-03 | Operability: trace context, latency histograms, live config reload and a load generator | v1 month 9 in one week, and the year's only observability week: SpiceDB and OpenFGA export Prometheus and OpenTelemetry (matrix: Management > metrics and tracing). |

## 2027-01 · Clients, engine speed, hardening and Raft

Weeks 10 to 13: the Go client with OpenAPI and a playground, compiled check plans and interning, fault injection with signed releases, then a hand-written Raft.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 10 | 2027-01-04 to 2027-01-10 | Clients and integrations: Go client, OpenAPI, middleware, watch consumer, playground | v1 month 10 in one week: adoption depends on clients and a place to try schemas (matrix: SDKs; Tooling > playground). |
| 11 | 2027-01-11 to 2027-01-17 | Check engine performance: compiled plans, interning, materialized membership, cache admission | v1 month 11 in one week: check latency and memory are where grantd should beat larger competitors (matrix: Performance). |
| 12 | 2027-01-18 to 2027-01-24 | Hardening and release engineering: fault injection, failover checker, signed releases | v1 month 12 in one week, and the year's only release-engineering week (matrix: Deployment > packaging; Security). |
| 13 | 2027-01-25 to 2027-01-31 | internal/raft: a tested Raft implementation | SpiceDB clusters and Okta FGA run highly available; manual promotion from week 7 is not enough (matrix: Scale > clustering and HA). |

## 2027-02 · Cluster, dispatch, materialization and PostgreSQL

An automatically failing-over replicated cluster, Zanzibar-style distributed dispatch, a Leopard-style materialized group index, and PostgreSQL as a datastore.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 14 | 2027-02-01 to 2027-02-07 | Replicated cluster with automatic failover | Enterprises need no manual step when a node dies (matrix: Scale > clustering and HA). |
| 15 | 2027-02-08 to 2027-02-14 | Distributed dispatch of check sub-problems | SpiceDB dispatches sub-problems over a consistent hash ring so each is cached in one place (matrix: Scale > distributed dispatch). |
| 16 | 2027-02-15 to 2027-02-21 | Materialized group membership index | AuthZed Materialize and Zanzibar's Leopard make deep nesting one lookup (matrix: Scale > materialization). |
| 17 | 2027-02-22 to 2027-02-28 | PostgreSQL datastore over a hand-written wire protocol client | SpiceDB and OpenFGA both run on PostgreSQL, and many teams require their existing database (matrix: Storage > PostgreSQL). |

## 2027-03 · Datastores, drop-in APIs, migration and console

MySQL and CockroachDB backends, SpiceDB-compatible gRPC and OpenFGA-compatible HTTP APIs, import and shadow-mode migration tools, and an admin console with the Q1 re-benchmark.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 18 | 2027-03-01 to 2027-03-07 | MySQL and CockroachDB datastores | SpiceDB supports MySQL and recommends CockroachDB for multi-region; OpenFGA supports MySQL (matrix: Storage > MySQL, CockroachDB). |
| 19 | 2027-03-08 to 2027-03-14 | SpiceDB-compatible gRPC API | Teams already using SpiceDB clients can switch without code changes, and gRPC is the main API of AuthZed and OpenFGA (matrix: APIs > gRPC and HTTP). |
| 20 | 2027-03-15 to 2027-03-21 | OpenFGA-compatible HTTP API and DSL | OpenFGA and Okta FGA share an API and DSL; compatibility opens grantd to their users (matrix: APIs > OpenFGA compatibility; Modelling > contextual tuples). |
| 21 | 2027-03-22 to 2027-03-28 | Migration tooling and shadow mode | Switching authorization systems is risky; Oso Migrate and import tools show buyers expect help (matrix: APIs > import and export; Tooling > migration). |
| 22 | 2027-03-29 to 2027-04-04 | Admin console, and the Q1 re-benchmark | Okta FGA, Permit.io and Oso Cloud sell consoles; OpenFGA has none (matrix: Management > admin console). |

## 2027-04 · Developer experience and policy breadth

A language server and editor extension, TypeScript, Python and Java SDKs, attribute policies with contextual relationships, and embeddable access-management components.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 23 | 2027-04-05 to 2027-04-11 | Language server and editor extension | Okta FGA, SpiceDB and Oso ship editor support (matrix: Tooling > IDE and language server). |
| 24 | 2027-04-12 to 2027-04-18 | SDKs for TypeScript, Python and Java | Competitors ship five or more SDKs; Go alone limits adoption (matrix: SDKs). |
| 25 | 2027-04-19 to 2027-04-25 | Attribute policies over relationships | Cerbos, OPA and Permit.io lead on attribute-based rules; grantd should combine both (matrix: Modelling > ABAC). |
| 26 | 2027-04-26 to 2027-05-02 | Embeddable access-management components | Permit.io Elements let host apps offer sharing and user management to their own users (matrix: Management > end-user access UI). |

## 2027-05 · Enterprise security and deployment

SSO and RBAC for admins, encryption at rest and in transit with a FIPS build, decision logs and compliance export, a Kubernetes operator, and multi-region reads with a failover drill.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 27 | 2027-05-03 to 2027-05-09 | SSO and RBAC for admins | Okta FGA, Permit.io and Oso Cloud give admins SSO and roles; SpiceDB and Cerbos keep them in paid tiers (matrix: Management > admin RBAC and SSO). |
| 28 | 2027-05-10 to 2027-05-16 | Encryption at rest and in transit, with a FIPS build | Regulated buyers require encrypted storage, TLS everywhere and FIPS cryptography (matrix: Security > encryption, FIPS). |
| 29 | 2027-05-17 to 2027-05-23 | Decision logs and compliance export | OPA, Cerbos Hub and Permit.io record every decision for audit and debugging (matrix: Management > decision logs). |
| 30 | 2027-05-24 to 2027-05-30 | Kubernetes operator and Helm chart | SpiceDB has an operator; enterprises deploy through Kubernetes (matrix: Deployment > Kubernetes operator, Helm). |
| 31 | 2027-05-31 to 2027-06-06 | Multi-region reads and a failover drill | Okta FGA runs active-active across regions and AuthZed sells multi-region (matrix: Scale > multi-region). |

## 2027-06 · Sharding to billions of relationships

Multi-Raft range sharding, cross-shard transactions with hybrid-clock tokens, placement and rebalancing, and cross-shard dispatch with a billion-relationship benchmark and the Q2 re-benchmark.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 32 | 2027-06-07 to 2027-06-13 | Multi-Raft range sharding | One Raft group caps write throughput and data size; Zanzibar and SpiceDB on Spanner scale by sharding (matrix: Scale > horizontal sharding). |
| 33 | 2027-06-14 to 2027-06-20 | Cross-shard transactions with hybrid-clock tokens | Atomic batches and consistency tokens must keep working across shards (matrix: Consistency > tokens at scale). |
| 34 | 2027-06-21 to 2027-06-27 | Placement and rebalancing | A sharded cluster needs automatic placement to stay balanced (matrix: Scale > horizontal sharding). |
| 35 | 2027-06-28 to 2027-07-04 | Cross-shard dispatch, a billion-relationship benchmark and the Q2 re-benchmark | Proving scale against SpiceDB's published 100-billion run needs a billion-relationship result on modest hardware (matrix: Performance). |

## 2027-07 · Governance and identity sync

Access reviews, what-if impact and schema analysis, time-travel queries over history, and a SCIM 2.0 server that syncs users and groups from identity providers.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 36 | 2027-07-05 to 2027-07-11 | Access reviews and who-has-access reports | Governance buyers need periodic access reviews (matrix: Governance > access reviews). |
| 37 | 2027-07-12 to 2027-07-18 | What-if impact and schema analysis | Changes to schemas and relationships should show their effect before they ship (matrix: Tooling > schema migrations and safety). |
| 38 | 2027-07-19 to 2027-07-25 | Time-travel queries over retained history | Audits ask who had access at a past date (matrix: Governance > historical queries). |
| 39 | 2027-07-26 to 2027-08-01 | SCIM 2.0 server for identity sync | Identity providers push users and groups by SCIM; Permit.io and others sync directories (matrix: Integrations > directory sync). |

## 2027-08 · Integrations and operations

Signed change-feed webhooks and connectors, a local decision point for low-latency checks, gateway integrations with steer, wicket, Envoy and Kubernetes, rolling upgrades, and deterministic simulation.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 40 | 2027-08-02 to 2027-08-08 | Change-feed webhooks and connectors | Watch is a strength; delivering it to systems that cannot hold a stream widens use (matrix: APIs > watch). |
| 41 | 2027-08-09 to 2027-08-15 | Local decision point for low-latency checks | Cerbos and Oso fallback nodes run next to apps; local checks remove network latency (matrix: Deployment > local decision point). |
| 42 | 2027-08-16 to 2027-08-22 | Gateway integrations: steer, wicket, Envoy and Kubernetes | Authorization belongs at the gateway too (matrix: Integrations > gateways). |
| 43 | 2027-08-23 to 2027-08-29 | Rolling upgrades and on-disk format versioning | Enterprises upgrade without downtime (matrix: Deployment > upgrades). |
| 44 | 2027-08-30 to 2027-09-05 | Deterministic simulation of the cluster | Distributed bugs need simulation (matrix: Security > reliability evidence). |

## 2027-09 · Footprint, lookups at scale, security and compliance

Memory per relationship cut again, lookups streamed over shards, a security hardening programme with fair scheduling, and data residency with subject erasure, plus the Q3 re-benchmark.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 45 | 2027-09-06 to 2027-09-12 | Memory footprint round two | No competitor publishes memory figures; grantd should own that row (matrix: Performance > memory per relationship). |
| 46 | 2027-09-13 to 2027-09-19 | Lookups streamed over shards | Lookups at scale must stream across ranges (matrix: APIs > lookup resources at scale). |
| 47 | 2027-09-20 to 2027-09-26 | Security hardening and fair scheduling | Shared services need abuse resistance (matrix: Security > limits and isolation). |
| 48 | 2027-09-27 to 2027-10-03 | Data residency, retention and subject erasure, and the Q3 re-benchmark | Compliance needs regional pinning and erasure (matrix: Security > compliance). |

## 2027-10 · Hosted mode, conformance and 1.0

Usage metering and quotas, a self-serve hosted service mode, conformance against SpiceDB and OpenFGA client suites, and a frozen 1.0 with the final benchmark.

| Week | Dates | Deliverable | Why |
|---:|---|---|---|
| 49 | 2027-10-04 to 2027-10-10 | Usage metering and quotas | Hosted competitors meter usage and enforce plan quotas (matrix: Management > usage and quotas). |
| 50 | 2027-10-11 to 2027-10-17 | Hosted service mode | Okta FGA, AuthZed Cloud and Oso Cloud are bought as services; grantd should run as one for many customers (matrix: Deployment > managed service). |
| 51 | 2027-10-18 to 2027-10-24 | Conformance against SpiceDB and OpenFGA client suites | Drop-in claims need the competitors' own tests (matrix: APIs > compatibility). |
| 52 | 2027-10-25 to 2027-10-31 | 1.0: frozen API, final benchmark and reference deployment | Enterprises adopt a 1.0 with guarantees (matrix: every row marked Oct 2027). |

## Next year

Gaps from the comparison still open after October 2027:

- Spanner as a datastore (SpiceDB supports it; it needs a cloud-specific client and is left out on purpose).
- SOC 2 Type II and other attestations for a hosted offering, which are organisational rather than code work.
- A policy language import from Rego or Cedar beyond attribute caveats.
- Ruby, .NET, PHP and Rust SDKs (Go, TypeScript, Python and Java ship this year).
- An IDE plugin for JetBrains editors (the language server works there, but no packaged plugin).
