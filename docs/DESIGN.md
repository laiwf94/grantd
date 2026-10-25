# toolgate design

## Goals

1. **Complete mediation.** Every tool call an agent makes passes one
   enforcement point that authenticates it, authorizes it against policy,
   limits it and records it. There is no path to a tool that skips a check
   (Saltzer and Schroeder's "complete mediation" and "fail-safe defaults" [1]).
2. **Least privilege per agent.** An agent sees and can call only what its
   policy grants, with arguments constrained to what the task needs. This is
   the mitigation OWASP gives for Excessive Agency [3]: minimize the
   functionality, permissions and autonomy an agent has. OWASP's agentic list
   calls the same failure tool misuse [4].
3. **A human for the risky calls**, bound to exactly what they approved.
4. **Evidence.** A record of every decision that an operator, or an auditor
   who does not trust the operator's disk, can verify.
5. **Fail closed.** When a check cannot be made (invalid policy, unwritable
   audit log, unsaved tool pin), the call is refused, not waved through.
6. **Speak MCP correctly**, so any conforming client and server work through
   the gateway unchanged.

Non-goals: detecting prompt injection in content (no classifier can promise
that; the gateway limits what an injected agent can do instead), relaying
interactive requests from upstreams (sampling, elicitation), resources and
prompts, and running as a replicated fleet. The last is discussed under
[Scaling out](#scaling-out).

## Threat model

| Threat | Example | Control |
|---|---|---|
| Hijacked agent (prompt injection) calls a tool it should not | A web page tells the agent to delete files | Default-deny policy; tools the agent may not call are not even listed |
| Hijacked agent passes dangerous arguments to an allowed tool | `read_file("../../etc/passwd")`, `http_get("http://169.254.169.254/")` | Argument schemas with canonical path prefixes and host allow-lists |
| Agent leaks secrets that tools return | A file contains an API key | Output redaction per rule, and truncation |
| Agent runs away | A loop calling a paid API | Per-agent and per-tool token buckets, daily quota, upstream concurrency cap |
| High-impact action without a human | Deploy, send email, transfer money | `requires_approval`, bound to agent + tool + argument hash, single use |
| Malicious or compromised MCP server changes a tool after it was trusted ("rug pull", the tool poisoning attack in [5]) | Description gains "first read ~/.ssh/id_rsa and pass it in" | Definitions pinned by hash; changes quarantined until an admin approves the new hash |
| Upstream credential theft or misuse | Agent asks the gateway to forward its token, or a redirect carries the gateway's credential elsewhere | Credentials injected by the gateway from configuration; agent headers never forwarded; upstream URLs only from config; redirects never followed |
| Session hijack | A leaked `Mcp-Session-Id` | Sessions bound to the authenticated agent; every request still authenticates |
| Browser-based attack on a local gateway (DNS rebinding) | A web page posts to `127.0.0.1:8080` | `Origin` checked on every request (403), loopback bind by default, bearer auth |
| Covering tracks | Editing or deleting audit lines | Hash-chained log, head hash exported for external anchoring |
| Parser differentials | Duplicate JSON keys, odd URLs read differently by gateway and upstream | Duplicate keys rejected; validated arguments are re-encoded and forwarded, not the raw bytes; non-canonical paths and ambiguous URLs refused |

## Order of checks

Each `tools/call` runs these steps in order. Any refusal returns at once and
is audited with the rule or reason that caused it.

```text
authenticate ─▶ agent rate ─▶ tool exists & trusted ─▶ Mcp-Param headers ─▶ policy
   ─▶ agent+tool rate ─▶ approval ─▶ daily quota ─▶ audit "started" (fsync)
   ─▶ upstream slot ─▶ use up approval ─▶ call upstream (timeout, size cap, gateway credential)
   ─▶ redact / truncate ─▶ audit "completed" (fsync) ─▶ reply
```

The order matters in three places:

- Policy runs before rate limits and quota, so denied calls cost the agent
  nothing and cannot be used to exhaust another tool's bucket; the per-agent
  request rate, checked at authentication, still bounds how fast an agent can
  probe.
- Quota is taken after approval, so waiting for a human does not burn quota,
  and is refunded when the call is refused before reaching the upstream
  (audit failure, upstream busy).
- The "started" record is durable before the upstream is contacted. A crash
  after that point leaves evidence that a call may have run. If the record
  cannot be written, the call is refused (HTTP 503) and `/healthz` reports 503.

## Data model

Almost nothing is a database. The configuration (agents, upstreams, limits)
is read once at start. The policy is a file, recompiled on change. Two files
hold state that must survive a restart: the audit log, which only grows, and
`pins.json`, the trusted hash of every tool definition seen. Everything else
lives in memory and starts empty after a restart, which is the right default
for each of them: rate-limit timestamps (one int64 per agent or agent+tool),
daily quota counters, open approval requests, and legacy MCP sessions. An
agent that loses a pending approval to a restart asks again; one that loses a
session gets a 404 and runs `initialize`, as the 2025 transport requires.

Tools are addressed as `upstream.tool`. Upstream names are restricted to
`[a-z][a-z0-9_-]{0,31}`, so the first dot always splits them, while tool names
may contain dots themselves (`admin.tools.list` on upstream `ops` is
`ops.admin.tools.list`).

## Policy

```json
{"version": 1, "rules": [
  {"id": "no-dotenv", "effect": "deny", "agents": ["*"], "upstreams": ["*"], "tools": ["read_file"],
   "arguments": {"required": ["path"], "properties": {"path": {"pattern": "(^|/)\\.env$"}}}},
  {"id": "read-workspace", "effect": "allow", "scopes": ["files:read"], "upstreams": ["fs"], "tools": ["read_file"],
   "arguments": {"type": "object", "required": ["path"], "additionalProperties": false,
                 "properties": {"path": {"type": "string", "x-path-prefix": ["reports"]}}},
   "output": {"redact": ["aws_access_key_id"], "max_bytes": 8192}},
  {"id": "deploy", "effect": "allow", "agents": ["release-bot"], "upstreams": ["ops"], "tools": ["deploy"],
   "requires_approval": true}
]}
```

**Semantics.** Default deny, and deny overrides allow, which is XACML's
"deny-overrides" combining algorithm [6]:

1. If any deny rule matches (subject, upstream, tool, and its argument schema
   when it has one), the first such rule denies.
2. Otherwise the first allow rule that matches, including its argument schema,
   allows, and its `requires_approval` and `output` settings apply.
3. Otherwise `default-deny`. If an allow rule matched everything but its
   argument schema, the decision names it and the validation error
   (`arguments rejected by rule read-workspace: $.path: ...`), so a well-meaning
   agent can correct itself.

A rule's subject is a list of agent ids (`"*"` for every authenticated agent)
and/or scopes; it matches if either matches. A deny rule's argument schema
says *when* to deny, so `required` matters: without `"required": ["path"]`,
the `no-dotenv` rule above would also deny calls that omit `path`.

Deny matching is a plain schema match on the arguments as sent; it does not
canonicalize them. That is why the allow-list keywords below are refused in
deny rules: they reject unusual input, so inside a deny rule exactly the
unusual input (`user@169.254.169.254`, an IPv4-mapped address) would not
match and would slip past. Limits on paths and hosts belong in allow rules,
where unusual input fails closed. Deny rules suit textual patterns, and
`x-path-prefix` makes those reliable by refusing paths with `..`, `.`,
repeated or trailing slashes before any rule sees them.

**Listing.** `tools/list` shows a tool when some allow rule could permit a
call to it and no unconditional deny forbids every call. A call to a tool the
agent cannot see is answered "Unknown tool", the same as a tool that does not
exist, so policy does not reveal what else is behind the gateway. The decision
is still audited as `default-deny`.

**Argument schemas** are a closed subset of JSON Schema 2020-12. Unsupported
keywords are compile errors rather than being ignored, because an ignored
`maxLenght` typo is an allow-everything rule. `pattern` uses Go's RE2 engine,
which runs in linear time, so a policy author cannot write a catastrophic
backtracking pattern; patterns are capped at 1 KiB and RE2 rejects counted
repetition above 1000. Compilation is bounded (depth 32, 2048 subschemas).

Two keywords cover the most common tool argument risks:

- `x-path-prefix`: the value must be a string holding a *canonical* path
  under one of the prefixes. Paths with `..` or `.` segments, repeated or
  trailing slashes, backslashes or control characters are refused instead of
  being cleaned (`secrets/.env/` is the same file as `secrets/.env` to most
  path libraries, but not to a pattern anchored at the end). Lexical cleaning is
  not what a file system does when a symlink precedes a `..`
  (`a/link/../b`), so cleaning and comparing would approve paths the upstream
  resolves elsewhere. The fake upstream additionally opens files through
  `os.Root`, so even an allowed path cannot escape its sandbox.
- `x-allowed-hosts`: the value must be a string holding an absolute
  `http`/`https` URL whose host is listed exactly, or matches `*.domain` (subdomains only), on the
  scheme's default port unless the entry names a port. URLs with user info,
  backslashes, spaces, non-ASCII or other bytes that URL parsers disagree about
  are refused, the class of bug Orange Tsai's SSRF research showed [7]. The
  check is on names: an allowed name that resolves to a private address is the
  upstream's concern (see Scaling out for an egress proxy).

**Hot reload.** The policy file is re-read every 2 s by default and applied
when its contents change (comparing a hash of the bytes, not size and mtime,
which miss a same-size edit within one mtime tick), and on `SIGHUP` and
`POST /admin/policy/reload`. A new policy is
parsed and compiled completely, then swapped in with one atomic pointer store;
evaluations in flight keep the policy they started with. A file that does not
parse, for example a half-written edit, is rejected, the previous policy stays
in force, and the rejection is audited once; the next good write is picked up.
Replacing the file by rename avoids the noise. Every audit record carries the hash of
the policy that decided it.

**Evaluation cost.** Rules are indexed by upstream at compile time (rules
naming `"*"` are merged into each upstream's list in file order), so a
decision scans only rules that can apply. A 200-rule policy decides in about
0.3 µs plus argument validation.

## Identity

**Static keys** are random strings (`toolgate token new` makes one with 260
bits of entropy). The configuration stores only their SHA-256, so the config
file is not a secret. Authentication hashes the presented key and compares it
with every configured hash using `subtle.ConstantTimeCompare` and
`ConstantTimeSelect`, so timing reveals neither which agent matched nor how
much of a key was right. A fast hash is enough here because the keys are
high-entropy; passwords would need a slow one.

**Signed tokens** are compact JWS (RFC 7515) with HMAC-SHA256 and JWT claims
(RFC 7519) [14]: `iss`, `aud`, `sub` (agent id), `owner`, `scope`, `iat`, `nbf`,
`exp`, `jti`. Following RFC 8725, the algorithm is fixed: a header naming any
`alg` other than `HS256` is refused, so `none` and algorithm confusion are not
possible. The `kid` selects among configured keys; tokens signed with an older
key stay valid while it is configured, and new tokens use the first key, which
is how keys rotate. `iss` and `aud` must match the gateway's, `exp - iat` may
not exceed the configured maximum (default one hour), and 30 seconds of clock
skew is allowed. The MAC is checked before the claims are parsed. Unknown
header fields and claims are refused, which also rules out `jku`/`x5u` key
fetching.

The issuer of signed tokens holds the signing key and is trusted: it can mint
any agent id with any scopes. Policy is the limit on what those scopes do.

## Human approval

When an allowed rule says `requires_approval`, the gateway computes a binding:
the agent id, the namespaced tool and the SHA-256 of the canonical arguments
(sorted keys, numbers as received). Then:

- An unused, unexpired approval for that binding lets the call continue. It
  is used up only after the quota, the "started" audit record and the
  upstream slot, so a call refused by any of those does not waste a human's
  decision. Using it up is an atomic delete under the store's lock, so twenty
  identical calls waiting on one approval let exactly one through (tested).
- A recent denial for that binding is reported (`-31005`) without asking the
  human again, until the pending TTL passes.
- Otherwise the existing pending request is joined, or a new one is opened and
  audited. The call waits up to `approvals.wait_seconds` for a decision; if
  none comes it returns `-31004` with the request id and expiry, and the agent
  retries the same call later. Retrying is the poll: no separate status
  endpoint is needed, and the retry goes through every other check again.

The administrator sees the exact canonical arguments
(`GET /admin/approvals/{id}`) and approves with a TTL (capped by
`max_grant_ttl_seconds`). Approvals use the admin token, a separate credential
from any agent's, so an agent cannot approve itself. Open requests are bounded
(16 per agent, 1024 in total) and kept in memory only; after a restart an
agent asks again.

## Rug-pull detection

A tool's definition is everything the model reads about it: name, title,
description, input and output schema, annotations. The gateway drops icons and
`_meta` (icon URLs are fetched by clients and are a tracking and SSRF surface)
and hashes the rest in canonical JSON, so an upstream that only reformats its
JSON does not trigger anything.

On first sight the hash is pinned (trust on first use) and persisted to
`TOOLGATE_STATE_DIR/pins.json` with a temp-file, fsync, rename, fsync-directory
sequence, so a restart cannot reset trust. When an upstream later serves a
different definition, the tool is quarantined: left out of every agent's list,
and calls are refused with `-31006`. The quarantine is audited and counted in
`toolgate_tools_quarantined`. An administrator reviews the pending definition
in `GET /admin/tools` and approves it by its hash. Approval is compare-and-set:
if the definition changed again since it was reviewed, the hash no longer
matches and the approval is refused. If the upstream reverts to the trusted
definition, the quarantine lifts by itself.

Tool lists are refreshed when older than the upstream's `tools_ttl_seconds`,
before a list or a call is served, and every 30 seconds in the background, so
a change is noticed within one TTL plus one refresh. While a refresh is
running, other callers use the last good list rather than queueing; a failed
refresh is not retried for 5 seconds, so a blackholed upstream costs one
timeout, not one per caller; upstreams are listed in parallel. Agents always receive the pinned
definition, which is the only one that has been reviewed. Pinning does not
cover a server that keeps its definition and changes what the tool *does*;
that needs the upstream to be trusted, or sandboxed, in the first place.

If a new pin cannot be saved, the tool is not trusted (fail closed).

## Audit log

Each line is one record:

```json
{"seq":7,"time":"…Z","prev":"<sha256 of line 6>","event":"tool_call","data":{"agent":"alice-bot","owner":"alice","auth":"static","upstream":"fs","tool":"read_file","decision":"allow","rule_id":"read-workspace","args_hmac":"…","args_preview":"{\"path\":\"reports/q1.txt\"}","policy":"<policy hash>","stage":"completed","outcome":"ok","latency_ms":3,"response_bytes":61,"redactions":0,"truncated":false,"request_id":"…"}}
```

`prev` is the SHA-256 of the previous line's exact bytes, forming a hash chain
in the manner of Crosby and Wallach's tamper-evident logging [8] and
Certificate Transparency [9]. Hashing the bytes as written, rather than a
re-serialization, means verification never depends on JSON formatting.
`toolgate audit verify` recomputes the chain: a modified line fails at that
line (its successor's `prev` no longer matches), a deleted or reordered line
fails at the sequence or link check, and the line number is reported.

A chain cannot detect the newest record being changed, or the tail being cut,
because those have no successor. For that the head hash must be stored
somewhere the attacker cannot write: `GET /admin/audit/head` serves it (and the
startup log prints it), and `audit verify -head <hash>` checks against it.
Shipping heads to a separate system periodically (or to a transparency log) is
the production answer.

**Durability.** A record is written with one `write` and fsynced before
`Append` returns. Concurrent appends share fsyncs: whoever acquires the sync
lock fsyncs everything written so far, covering every caller queued behind it
(group commit). On macOS (`F_FULLFSYNC`, 4 to 7 ms per call on the test
machine) that turns one fsync per record for a single writer into 64 to
122 µs per record for 16 concurrent writers. If a write fails half way,
the partial bytes are truncated off; if that fails, or if an fsync fails, the
log refuses all further appends, because after a failed fsync the page cache
can no longer be trusted to reach the disk (the lesson of PostgreSQL's
"fsyncgate" [10]). The gateway then refuses calls until restarted.

On start the whole log is verified. A torn final line (a write that was never
acknowledged) is cut off; any other damage stops startup with the line number.
The tests cut a log at every byte offset and flip every single byte.

**What is recorded about arguments.** Never the raw values. `args_hmac` is an
HMAC-SHA256 under `TOOLGATE_AUDIT_KEY`, so the same arguments can be
correlated across records but a short secret cannot be recovered by hashing
guesses (which an unkeyed SHA-256 would allow). `args_preview` is at most 256
characters, with values under sensitive-looking keys (`password`, `token`,
`api_key`, ...) and every built-in credential shape replaced.

## Serving MCP

The gateway targets the current revision, **2026-07-28** [2], and also serves the
handshake-based revisions **2025-11-25**, **2025-06-18** and **2025-03-26**,
which the specification calls a "dual-era" server. Most deployed clients and
servers still speak the older revisions, so a gateway that only spoke the new
one would break them.

A request is routed by how it opens:

| Request | Era |
|---|---|
| `initialize` | Legacy: negotiate (the requested version if supported, else 2025-11-25), mint a 256-bit `Mcp-Session-Id` bound to the agent |
| `MCP-Protocol-Version: 2026-07-28` | Modern: stateless |
| `Mcp-Session-Id` present | Legacy session: unknown, expired or someone else's session is 404 |
| no version header | 400 `-32020`, listing supported versions |
| a legacy version without a session | 400: send `initialize` first |
| an unknown version | 400 `-32022` with `supported` and `requested` |

Modern requests must carry `_meta.io.modelcontextprotocol/protocolVersion`
(equal to the header) and `clientCapabilities`; `Mcp-Method` must equal the
body's method and `Mcp-Name` the tool name (after base64 sentinel decoding).
Mismatches are 400 `-32020`, because a load balancer routing on headers and a
server acting on the body must not disagree. For tools whose schema marks
arguments with `x-mcp-header`, the gateway checks the agent's
`Mcp-Param-{Name}` headers against the arguments, rejects tool definitions
whose annotations break the specification's constraints, and sends correct
headers upstream. Results carry `resultType` and `serverInfo`; `tools/list`
says `cacheScope: "private"`, since it depends on the caller's credentials.

Common to both eras: one JSON-RPC message per POST (batches were removed in
2025-06-18 and are refused with `-32600`); request ids are strings or
integers, never null; notifications get 202 with no body; a client may not send
responses (the gateway sends no requests); `Origin`, when present, must be in
`TOOLGATE_ALLOWED_ORIGINS` or the request is 403 (DNS-rebinding protection);
`Accept` must allow JSON; the body is capped at 1 MiB before it is read;
nesting is capped at 64; invalid UTF-8 and duplicate object keys are parse
errors. GET is 405, since the gateway offers no standalone stream.

**As a client** to upstreams the gateway speaks 2026-07-28 first. An HTTP 400,
404 or 405 without a recognized modern error means a legacy server: it runs
`initialize`, keeps the session, and re-initializes once when the server says
the session is gone. Responses may be JSON or SSE; SSE streams are parsed up to
the response with the request's id, skipping notifications. It declares no
client capabilities, so a conforming upstream will not return
`input_required`; if one does anyway, the call fails rather than relaying an
interactive request the agent never agreed to.

## Failure modes

| Failure | Behavior |
|---|---|
| Policy file invalid or half written | Rejected; previous policy stays; audited as `policy_rejected` |
| Audit log write or fsync fails | Calls refused with 503 `-31010`; `/healthz` 503; restart required |
| Audit log tampered while stopped | Startup refuses with the line number |
| Crash mid-append | Torn last line removed on start; it was never acknowledged |
| Pin store cannot be written | New tools not trusted; quarantines still enforced in memory |
| Upstream down | Its last good tool list is still used (pins still checked); a never-reached upstream lists nothing; calls get 502 `-31007` |
| Upstream slow | Call cancelled at `timeout_ms`, 504 `-31008` |
| Upstream floods | Response capped at `max_response_bytes`, 502 |
| Upstream redirects | Not followed (the credential would go along), 502 |
| Upstream at concurrency limit | Waits up to 1 s, then 429 `-31009` with `Retry-After` |
| Gateway restart | Pins and audit chain persist; rate buckets, quotas, sessions and approval requests reset |

## Limits

| Limit | Value | Why |
|---|---|---|
| Request body | 1 MiB | Read through `MaxBytesReader` before parsing |
| JSON nesting | 64 | Bounds parser and validator recursion |
| Policy file / rules | 1 MiB / 1000 | Bounds compile time and memory |
| Schema depth / subschemas / pattern | 32 / 2048 / 1 KiB | Bounds compile and validation cost |
| Tools per upstream | 1000 | Bounds pin store and list size |
| Upstream response | 1 KiB to 16 MiB (default 1 MiB) | Configurable per upstream |
| Upstream response headers | 64 KiB | A hostile upstream cannot exhaust memory with headers |
| Upstream timeout | 100 ms to 120 s (default 10 s) | Configurable per upstream |
| Signed token size / lifetime | 4 KiB / 1 h default, 24 h max | Short-lived credentials |
| Open approvals | 16 per agent, 1024 total | Memory and admin attention |
| Legacy sessions | 32 per agent (LRU), 10,000 total, 30 min idle | Memory; an agent re-initializing in a loop evicts its own |
| Audit record | 1 MiB | One line, one write |
| Argument preview | 256 characters | Enough to read, too short to leak much |
| HTTP | 5 s header read, 15 s body read, 6 min write, 32 KiB headers | Slow-client protection; the write timeout covers the worst case for one call (list refresh, approval wait, slot wait and upstream call at their maximums) |

## Security notes

- Admin and agent APIs listen on separate addresses, both on loopback by
  default. The admin API always requires its own token (32+ characters),
  compared in constant time; agent credentials are useless there.
- No secret reaches a log: tokens are never logged, upstream credentials come
  from environment variables named in the config, error messages name the
  variable rather than its value, and internal errors return a request id with
  the details only in the server log.
- Upstream error messages are passed to agents only cut to 200 bytes and
  through the rule's redaction patterns as well as the built-in ones.
- The HTTP transport for upstreams ignores proxy environment variables, so
  traffic cannot be rerouted by the environment.
- Request ids in logs and audit records are always generated by the
  gateway. A client's `X-Request-Id` is logged separately, and only if it
  matches `^[A-Za-z0-9._:-]{1,128}$`, so an agent cannot choose or reuse the
  id that ties its audit records together.
- The container image is distroless, runs as `nonroot`, and has no shell.

## Scaling out

What would change to run this for many agents across machines:

1. **Shared counters.** Buckets and quotas live in each gateway's memory, so
   N replicas allow N times the rate. GCRA [13] needs only one timestamp per key,
   which maps directly onto an atomic compare-and-set in Redis or a similar
   store (the approach of redis-cell [11]); quotas become per-day counters there.
2. **Shared approvals and pins.** Move both stores into a small transactional
   database. Approval consumption is already a single compare-and-delete, so
   it translates to a conditional delete; pin approval is a compare-and-set on
   the hash.
3. **Audit pipeline.** Keep the local hash-chained file as the write-ahead
   record, ship records to a central append-only store, and publish chain
   heads (or a Merkle tree head, as Certificate Transparency does) somewhere
   the gateway operators cannot rewrite.
4. **Identity from the platform.** Replace shared-secret tokens with
   asymmetric ones verified against the identity provider's JWKS (pinned
   issuer, no key fetching from token headers), or workload identity such as
   SPIFFE [12], and OAuth resource indicators per the MCP authorization
   specification.
5. **Egress control.** Put upstream traffic, and the tools' own outbound
   traffic, behind an egress proxy that resolves names and blocks private
   ranges at connect time, closing the DNS gap left by name-based allow-lists.
6. **Policy distribution.** Serve signed policy bundles from a control plane
   and keep the same compile-then-swap reload, so every replica changes policy
   atomically and reports the hash it is enforcing.

## References

1. Jerome H. Saltzer and Michael D. Schroeder, "The Protection of Information in Computer Systems". https://www.cs.virginia.edu/~evans/cs551/saltzer/
2. Model Context Protocol specification, revision 2026-07-28 (and the 2025-11-25 transport and lifecycle pages). https://modelcontextprotocol.io/specification/2026-07-28
3. OWASP GenAI Security Project, "LLM06 Excessive Agency" and "LLM01 Prompt Injection". https://genai.owasp.org/llmrisk/llm062025-excessive-agency/, https://genai.owasp.org/llmrisk/llm01-prompt-injection/
4. OWASP GenAI Security Project, "Top 10 for Agentic Applications" (ASI02, tool misuse). https://genai.owasp.org/
5. Luca Beurer-Kellner and Marc Fischer, "MCP Security Notification: Tool Poisoning Attacks". https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
6. OASIS, "eXtensible Access Control Markup Language (XACML) Version 3.0", deny-overrides combining algorithm. https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html
7. Orange Tsai, "A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages". https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
8. Scott A. Crosby and Dan S. Wallach, "Efficient Data Structures for Tamper-Evident Logging". https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf
9. Ben Laurie, Adam Langley and Emilia Kasper, "Certificate Transparency", RFC 6962. https://www.rfc-editor.org/rfc/rfc6962
10. Jonathan Corbet, "PostgreSQL's fsync() surprise". https://lwn.net/Articles/752063/
11. Brandur Leach, "redis-cell", GCRA rate limiting as a Redis module. https://github.com/brandur/redis-cell
12. SPIFFE, "Secure Production Identity Framework for Everyone". https://spiffe.io/
13. ITU-T Recommendation I.371, "Traffic control and congestion control in B-ISDN" (GCRA). https://www.itu.int/rec/T-REC-I.371
14. RFC 7515 (JWS), RFC 7519 (JWT), RFC 8725 (JWT best current practices). https://www.rfc-editor.org/rfc/rfc7515, https://www.rfc-editor.org/rfc/rfc7519, https://www.rfc-editor.org/rfc/rfc8725
