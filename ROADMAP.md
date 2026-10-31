# toolgate roadmap, November 2026 to October 2027

By October 2027 toolgate is an enterprise MCP security gateway at feature parity with the category leaders (Kong AI Gateway, Azure API Management, Cloudflare MCP server portals, agentgateway and IBM ContextForge) on protocol coverage, OAuth 2.1 and SSO, multi-tenancy, RBAC, a web console, REST and gRPC to MCP, guardrails, sandboxed local servers, high availability and Kubernetes, and ahead of them on the controls only a dedicated security gateway has: argument-level default-deny policy, tool pinning, session data-flow labels, two-person approval and a Merkle-provable audit log. It stays one static Go binary with no third-party dependencies, an embedded Raft store instead of an external database, and a published, CI-enforced benchmark that holds it under 20 MB idle memory, 50 ms cold start and 1 ms p99 added latency.

Benchmark products: Kong AI Gateway, Azure API Management, Cloudflare MCP server portals, agentgateway, IBM ContextForge, Docker MCP Gateway and Lasso MCP Gateway. Every week's why names the matrix row it closes.

Weeks 1 to 12 deliver the twelve v1 monthly themes, one per week. Weeks 13 to 52 are new enterprise capabilities and the quarterly benchmark work.

Performance targets: measured against agentgateway and Kong on the same 4 vCPU Linux host: static binary under 25 MB, distroless image under 30 MB, idle RSS under 20 MB, RSS under 150 MB at 10,000 agents, cold start to first served call under 50 ms, p99 added latency under 1 ms at 10,000 calls per second (audit in group commit), and denied-path throughput above 50,000 calls per second.

## 2026-11 · Policy toolchain, audit evidence, federated identity, richer policy and approvals

The first five v1 monthly themes, one per week: policy test and lint with an egress guard and crash safety, a rotated and Merkle-provable audit log, asymmetric federated identity, policy with windows, budgets and result rules, and a real approval workflow.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 1 | 2026-11-02 to 2026-11-08 | Policy tooling, egress hardening and crash safety | v1 theme 1 in one week. Matrix rows Authorization > Policy test and lint, Safety > Egress SSRF guard, Ops > Graceful drain: no competitor in the matrix ships a policy test runner or linter, and a name-based allow-list still leaves the DNS gap open. |
| 2 | 2026-11-09 to 2026-11-15 | Audit evidence: rotation, signed checkpoints, Merkle proofs and query | v1 theme 2 in one week. Matrix rows Audit > Tamper-evident log and Audit > Inclusion proofs: competitors offer log viewers and export, none offers a signed, provable record an auditor can check without trusting the operator. |
| 3 | 2026-11-16 to 2026-11-22 | Federated identity: asymmetric tokens, JWKS, protected resource metadata and live keys | v1 theme 3 in one week. Matrix rows Identity > JWT with JWKS and Identity > MCP authorization (resource server): agentgateway, Kong and Azure API Management validate issuer tokens; toolgate only has shared-secret tokens. |
| 4 | 2026-11-23 to 2026-11-29 | Richer policy: time windows, per-rule budgets, result rules and decision explain | v1 theme 4 in one week. Matrix rows Traffic > Quotas and budgets per tool and Authorization > Result rules: Azure API Management and Kong limit per API, toolgate will limit per rule and per argument and judge what tools return. |
| 5 | 2026-11-30 to 2026-12-06 | Approval workflow: named approvers, two-person rule, signed notifications, durability and an admin page | v1 theme 5 in one week. Matrix rows Safety > Human approval and Safety > Two-person approval: none of the commercial gateways in the matrix documents human approval of a single tool call. |

## 2026-12 · Protocol coverage, shared replica state, policy distribution and operability

v1 monthly themes 6 to 9, one per week: resources, prompts and stdio servers under policy, rate limits, pins and approvals shared across replicas, signed policy bundles with audit shipping, and the operability work that makes a fleet manageable.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 6 | 2026-12-07 to 2026-12-13 | Protocol coverage: resources, prompts, stdio upstreams and live list changes | v1 theme 6 in one week. Matrix rows Protocol > Resources, Protocol > Prompts and Protocol > stdio servers: ContextForge serves resources and prompts and Azure API Management does not; agentgateway and Docker run stdio servers. |
| 7 | 2026-12-14 to 2026-12-20 | Shared state for replicas: rate limits, quotas, pins and approvals | v1 theme 7 in one week. Matrix row Ops > High availability: Kong, ContextForge and agentgateway run several replicas, while toolgate's limits and approvals live in one process. |
| 8 | 2026-12-21 to 2026-12-27 | Policy distribution and audit shipping | v1 theme 8 in one week. Matrix rows Ops > Policy distribution and Audit > Log export: Kong and Azure API Management push configuration from a control plane and Cloudflare exports logs with Logpush. |
| 9 | 2026-12-28 to 2027-01-03 | Operability: tracing, stage metrics, live config and upstream health | v1 theme 9 in one week, the only observability week of the year. Matrix row Ops > OpenTelemetry: agentgateway and ContextForge export OpenTelemetry traces and metrics. |

## 2027-01 · Benchmark against the leaders, security assurance, ecosystem and the storage engine

The last three v1 themes, one week each, including the first published benchmark against agentgateway and Kong with a CI regression gate, then the embedded encrypted storage engine every later enterprise feature builds on.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 10 | 2027-01-04 to 2027-01-10 | Performance on Linux and a published benchmark against the leaders | v1 theme 10 in one week, plus the lightweight goal from the brief. Matrix rows Footprint > Memory, Cold start, p99 and Throughput: agentgateway (Rust) and Kong (NGINX) are the reference points. Targets, measured against agentgateway and Kong on the same 4 vCPU Linux host: static binary under 25 MB, distroless image under 30 MB, idle RSS under 20 MB, RSS under 150 MB at 10,000 agents, cold start to first served call under 50 ms, p99 added latency under 1 ms at 10,000 calls per second (audit in group commit), and denied-path throughput above 50,000 calls per second. |
| 11 | 2027-01-11 to 2027-01-17 | Security assurance: attack corpus, differential parsing, verifiable releases and secret handling | v1 theme 11 in one week. Matrix rows Safety > Attack regression suite and Ops > Verifiable releases: a security gateway has to prove its controls on every commit and let users verify the binary they run. |
| 12 | 2027-01-18 to 2027-01-24 | Ecosystem: policy templates, Kubernetes manifests and an embeddable Go library | v1 theme 12 in one week, with the 1.0 freeze moved to the last week of the year because forty enterprise weeks still change formats. Matrix rows Ops > Kubernetes deployment and Protocol > Embeddable library. |
| 13 | 2027-01-25 to 2027-01-31 | Embedded storage engine with encryption at rest | New. Matrix rows Ops > No external database and Security > Encryption at rest: ContextForge needs Redis and a database, Kong needs Postgres for clustering. An embedded transactional store lets toolgate keep one binary and is the base for Raft, tenants and the console. |

## 2027-02 · Expressive policy and the OAuth 2.1 authorization server

Bring the policy language to CEL-level expressiveness with safe simulation, and make toolgate a full OAuth 2.1 authorization server and per-user credential broker for MCP clients.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 14 | 2027-02-01 to 2027-02-07 | CEL-compatible policy expressions | Matrix row Authorization > Policy language: agentgateway authorizes with CEL; toolgate rules cannot relate values (owner equals agent's owner, amount below a ceiling). A typed, cost-bounded CEL subset keeps per-call evaluation safe and familiar. |
| 15 | 2027-02-08 to 2027-02-14 | Policy simulation: replay, shadow rules and impact reports | Matrix row Authorization > Policy simulation: no product in the matrix shows what a policy change would have done to real traffic. Replay plus shadow rules turns a risky edit into a reviewed diff. |
| 16 | 2027-02-15 to 2027-02-21 | Built-in OAuth 2.1 authorization server with dynamic client registration | Matrix row Identity > Built-in authorization server: Cloudflare portals and ContextForge handle sign-in for MCP clients; toolgate needs an external issuer. A built-in server with PKCE, DCR and consent lets it stand alone. |
| 17 | 2027-02-22 to 2027-02-28 | Per-user credential broker: upstream OAuth, token exchange and an encrypted vault | Matrix row Identity > Per-user upstream credentials: Cloudflare portals and ContextForge let each user authorize upstream servers with their own account. toolgate shares one credential per upstream, so tools cannot tell whose authority a call carries. |

## 2027-03 · Enterprise administration: SSO, RBAC, tenants, API and console

Everything an enterprise buyer checks first: single sign-on and scoped roles for administrators, hard multi-tenancy, a versioned admin API with declarative configuration, and a full web console with usage analytics.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 18 | 2027-03-01 to 2027-03-07 | Admin single sign-on and role-based access | Matrix rows Ops > Admin SSO and Ops > Admin RBAC: Kong Enterprise, Azure API Management, Cloudflare and ContextForge all give administrators SSO and scoped roles. toolgate has one admin token. |
| 19 | 2027-03-08 to 2027-03-14 | Multi-tenancy with hard isolation | Matrix row Ops > Multi-tenancy: Kong workspaces, Cloudflare accounts and ContextForge teams separate groups of users. Tenants let one fleet serve many teams without seeing each other. |
| 20 | 2027-03-15 to 2027-03-21 | Versioned admin API, OpenAPI and declarative configuration | Matrix row Ops > Admin API and IaC: Azure API Management manages MCP servers through REST, Bicep and Terraform, and Kong through decK. toolgate needs a stable API and a GitOps path. |
| 21 | 2027-03-22 to 2027-03-28 | Web admin console | Matrix row Ops > Admin UI: Kong Manager, the Azure portal, Cloudflare's dashboard, ContextForge and agentgateway all have a UI. toolgate's v1 page covers approvals only; the console covers everything, server-rendered with no JavaScript framework. |
| 22 | 2027-03-29 to 2027-04-04 | Usage analytics and cost reporting | Matrix row Ops > Usage analytics: Cloudflare and Kong show traffic per server and consumer. Teams need calls, denials, approvals and cost per agent, tool and tenant without an external analytics stack. |

## 2027-04 · Full MCP surface, virtual servers and the second benchmark

Mediate the rest of the protocol (sampling, elicitation, roots, tasks and streaming), add virtual servers like the portals offer, and re-measure the benchmark with a zero-allocation hot path.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 23 | 2027-04-05 to 2027-04-11 | Sampling, elicitation and roots under policy | Matrix row Protocol > Sampling and elicitation: none of the gateways in the matrix documents mediating these server-initiated requests. Relaying them blindly lets a malicious server drive the model; refusing them breaks legitimate servers. |
| 24 | 2027-04-12 to 2027-04-18 | Long-running calls: tasks, progress, cancellation and resumable streams | Matrix row Protocol > Tasks and streaming: real tools run for minutes. The gateway must stream progress, pass cancellation both ways, survive client reconnects and keep the audit record truthful about what finished. |
| 25 | 2027-04-19 to 2027-04-25 | Virtual servers: aggregation, aliases and per-tool switches | Matrix row Protocol > Virtual servers: Cloudflare portals expose up to 80 servers on one endpoint with aliases and per-tool switches, and ContextForge bundles tools into virtual servers. toolgate exposes one flat namespace per agent. |
| 26 | 2027-04-26 to 2027-05-02 | Performance II: zero-allocation hot path and quarterly benchmark | Matrix rows Footprint > p99 and Throughput, first quarterly re-measure. Ten feature weeks since January must not erode the targets. Targets, measured against agentgateway and Kong on the same 4 vCPU Linux host: static binary under 25 MB, distroless image under 30 MB, idle RSS under 20 MB, RSS under 150 MB at 10,000 agents, cold start to first served call under 50 ms, p99 added latency under 1 ms at 10,000 calls per second (audit in group commit), and denied-path throughput above 50,000 calls per second. |

## 2027-05 · APIs as tools and the data-flow defence

Turn existing REST, gRPC and GraphQL services into governed MCP tools, cut tool-list context cost, and stop exfiltration chains with session data-flow labels and content inspection.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 27 | 2027-05-03 to 2027-05-09 | REST and OpenAPI to MCP | Matrix row Protocol > REST to MCP: Kong, Azure API Management, ContextForge and agentgateway all turn APIs into tools. Without it every internal API needs a hand-written MCP server. |
| 28 | 2027-05-10 to 2027-05-16 | gRPC and GraphQL to MCP | Matrix row Protocol > gRPC to MCP: ContextForge translates gRPC services through reflection. Many internal services speak only gRPC or GraphQL. |
| 29 | 2027-05-17 to 2027-05-23 | Context optimisation: tool search and lazy definitions | Matrix row Protocol > Context optimisation: Cloudflare portals offer context optimisation and Code Mode to cut tokens. Hundreds of tool definitions waste model context and degrade tool choice. |
| 30 | 2027-05-24 to 2027-05-30 | Session data-flow labels and exfiltration rules | Matrix row Safety > Data-flow control: no gateway in the matrix tracks what a session has read. An agent holding private data that then reads untrusted content can be told to send that data anywhere. |
| 31 | 2027-05-31 to 2027-06-06 | Content inspection: personal data, secrets and hidden instructions | Matrix row Safety > PII and DLP: Cloudflare applies DLP profiles, Lasso masks PII and secrets, and agentgateway runs regex guardrails. toolgate redacts credential shapes only. |

## 2027-06 · Guardrails and isolation for local servers

Plug in external guardrails and score definitions on first sight, let upstreams verify they were called through the gateway, and confine local servers with kernel sandboxes and containers.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 32 | 2027-06-07 to 2027-06-13 | External guardrails and definition risk analysis | Matrix rows Safety > External guardrails and Safety > Definition scanning: agentgateway calls guardrail webhooks and Lasso scans descriptions and server reputation. toolgate pins definitions but does not judge them. |
| 33 | 2027-06-14 to 2027-06-20 | Gateway-signed call assertions | Matrix row Safety > Signed call assertions: an upstream cannot tell a mediated call from a direct one, so a leaked upstream credential bypasses every control. No product in the matrix offers this. |
| 34 | 2027-06-21 to 2027-06-27 | Linux sandbox for local servers: namespaces, seccomp and Landlock | Matrix row Safety > Server isolation: Docker MCP Gateway runs servers in restricted containers. A kernel sandbox gives the same confinement with no container runtime and no new dependency. |
| 35 | 2027-06-28 to 2027-07-04 | Container runner for MCP servers | Matrix rows Safety > Server isolation and Ops > Registry: Docker MCP Gateway launches catalog servers as containers. Teams that package servers as images want the same, under toolgate's policy. |

## 2027-07 · Registry, desktop mode and consensus

An internal server registry with hash pinning, a desktop front end for local clients, and the Raft core and cluster management that remove the need for an external store.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 36 | 2027-07-05 to 2027-07-11 | Server registry and catalog with hash pinning | Matrix row Ops > Registry: Kong's MCP Registry, Azure API Center and Docker's catalog let teams discover approved servers. toolgate pins definitions, not the code behind them. |
| 37 | 2027-07-12 to 2027-07-18 | Desktop mode: toolgate as a local front end | Matrix row Protocol > Local client integration: Docker MCP Gateway and Lasso run next to desktop clients. A stdio front end puts every local server call under policy with no client changes. |
| 38 | 2027-07-19 to 2027-07-25 | Raft core: election and log replication | Matrix row Ops > High availability without an external store: Kong needs Postgres and ContextForge Redis for clustering. Raft on the embedded store keeps toolgate one binary. |
| 39 | 2027-07-26 to 2027-08-01 | Raft snapshots, membership changes and linearizable reads | Matrix row Ops > High availability: a production cluster must compact its log, add and remove nodes safely and serve reads that are never stale. |

## 2027-08 · Replicated fleet, federation, recovery and the third benchmark

Move fail-closed state onto Raft with leased rate limits, prove it under faults, federate gateways across regions, add backups and point-in-time restore, and re-measure footprint with response caching.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 40 | 2027-08-02 to 2027-08-08 | Replicated gateway state with leased rate limits | Matrix row Ops > High availability: the shared RESP store from December becomes optional. Pins, approvals, keys, tenants, tasks and policy move onto Raft, and rate limits use leased budgets with bounded overshoot. |
| 41 | 2027-08-09 to 2027-08-15 | Fault injection and linearizability checking | Matrix row Ops > Proven high availability: claims about a replicated security gateway mean little without a test that tries to break them. |
| 42 | 2027-08-16 to 2027-08-22 | Multi-region federation | Matrix row Ops > Federation: ContextForge federates gateways across regions and clusters. Global teams need regional gateways with shared policy and data kept in region. |
| 43 | 2027-08-23 to 2027-08-29 | Backups, point-in-time restore and disaster recovery | Matrix row Ops > Backups: managed products back up for you; a self-hosted gateway has to offer the same with proof that restores work. |
| 44 | 2027-08-30 to 2027-09-05 | Performance III: cold start, footprint and response caching | Matrix rows Footprint > Cold start and Memory, Traffic > Response caching (Azure API Management caches tool responses); second quarterly re-measure. Targets, measured against agentgateway and Kong on the same 4 vCPU Linux host: static binary under 25 MB, distroless image under 30 MB, idle RSS under 20 MB, RSS under 150 MB at 10,000 agents, cold start to first served call under 50 ms, p99 added latency under 1 ms at 10,000 calls per second (audit in group commit), and denied-path throughput above 50,000 calls per second. |

## 2027-09 · Kubernetes, agent-to-agent, compliance and approval delivery

Run natively on Kubernetes with a controller and Gateway API, mediate agent-to-agent traffic, export compliance-grade logs, and deliver approvals where approvers work.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 45 | 2027-09-06 to 2027-09-12 | Kubernetes controller and Gateway API | Matrix row Ops > Kubernetes controller: agentgateway and Kong ship controllers with Gateway API support. January's manifests deploy toolgate but do not manage policy and upstreams as resources. |
| 46 | 2027-09-13 to 2027-09-19 | Agent-to-agent gateway | Matrix row Protocol > A2A: agentgateway and ContextForge mediate agent-to-agent traffic. Agents calling agents need the same identity, policy, labels and audit as agents calling tools. |
| 47 | 2027-09-20 to 2027-09-26 | Compliance exports and evidence reports | Matrix row Audit > SIEM export: Cloudflare Logpush and Azure Monitor feed security teams. Compliance teams also need standard formats and evidence packs for reviews. |
| 48 | 2027-09-27 to 2027-10-03 | Approval delivery: chat actions, email, escalation and standing grants | Matrix row Safety > Human approval: approvers will not watch a console. Requests must reach them where they work, escalate on timeout, and routine work needs narrow standing grants. |

## 2027-10 · SDKs, conformance, final benchmark and 1.0

Client libraries for automation, a public conformance and interop matrix, the final benchmark against the leaders, and 1.0 with stable formats and migrations.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 49 | 2027-10-04 to 2027-10-10 | Python and TypeScript SDKs | Matrix row Ops > SDKs and IaC: Kong and Azure API Management ship SDKs and IaC tooling. Approval bots and provisioning scripts are written in Python and TypeScript. |
| 50 | 2027-10-11 to 2027-10-17 | MCP conformance suite and client interop matrix | Matrix row Protocol > Conformance: buyers ask which clients and servers work through a gateway. A public matrix, run in CI, answers it with evidence. |
| 51 | 2027-10-18 to 2027-10-24 | Performance IV: final benchmark against the leaders | Matrix rows Footprint, the last quarterly re-measure and the year's published result. Targets, measured against agentgateway and Kong on the same 4 vCPU Linux host: static binary under 25 MB, distroless image under 30 MB, idle RSS under 20 MB, RSS under 150 MB at 10,000 agents, cold start to first served call under 50 ms, p99 added latency under 1 ms at 10,000 calls per second (audit in group commit), and denied-path throughput above 50,000 calls per second. |
| 52 | 2027-10-25 to 2027-10-31 | 1.0 with stable formats and migrations | Matrix row Ops > Upgrades: v1's last week, moved here because the enterprise weeks change formats. 1.0 promises compatibility for config, policy, store, audit and API formats. |

## Next year

Gaps from the comparison matrix left open after October 2027:

- LLM provider routing, prompt guardrails and token budgets for model traffic (agentgateway, Kong AI Gateway): outside a tool gateway's core; integrate with a model gateway instead of duplicating one
- Managed SaaS offering with a hosted control plane (Cloudflare, Azure API Management, Kong Konnect)
- Terraform provider (Azure API Management, Kong): needs the provider framework as a dependency, so it belongs in a separate repository built on the /v1 API
- Hardware security module and KMS-native signing for audit checkpoints and assertions beyond the HTTP KMS interface
- Formal verification of the approval and lease protocols in TLA+, beyond the simulator and linearizability checks
