# toolgate

A security gateway that sits between AI agents and the tools they call over
the [Model Context Protocol](https://modelcontextprotocol.io/specification/2026-07-28)
(MCP). Every tool call is authenticated, checked against a declarative policy,
rate limited, optionally approved by a human, and written to a tamper-evident
audit log before it reaches the real MCP server.

Written in Go with the standard library only (no third-party dependencies).

```json
{
  "id": "read-workspace",
  "effect": "allow",
  "scopes": ["files:read"],
  "upstreams": ["fake"],
  "tools": ["read_file"],
  "arguments": {
    "type": "object", "required": ["path"], "additionalProperties": false,
    "properties": {"path": {"type": "string", "maxLength": 256, "x-path-prefix": ["reports", "notes"]}}
  },
  "output": {"redact": ["aws_access_key_id", "private_key"], "max_bytes": 8192}
}
```

```console
$ ./examples/demo.sh
3. Argument constraints: path traversal, a .env file, and an SSRF attempt
   HTTP 200  error -31001: denied by policy: arguments rejected by rule read-workspace: $.path: path must not contain ".." segments  rule_id=default-deny
   HTTP 200  error -31001: denied by policy: rule no-dotenv forbids this call  rule_id=no-dotenv
   HTTP 200  error -31001: denied by policy: arguments rejected by rule web-allowlist: $.url: URL host is not in the allowed list  rule_id=default-deny
...
7. Rug pull: the upstream swaps the translate tool's description for one with injected instructions
   alice-bot's tool list no longer offers it:
   fake.echo, fake.http_get, fake.read_file
   HTTP 200  error -31006: tool fake.translate changed its definition and is quarantined until an administrator reviews it
...
8. The audit log is a hash chain
   OK audit.jsonl: 23 records, head bcb6d990…
   someone rewrites line 3 to turn a denial into an allow...
   FAIL audit.jsonl: line 3: record does not match the hash stored in line 4: it was modified, removed or reordered
```

## Why

An agent that can call tools acts with whatever authority those tools have,
and anything it reads (a web page, a file, a tool description) can try to
steer it. OWASP lists this as
[LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and
[LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/),
and the [Top 10 for Agentic Applications](https://genai.owasp.org/) as tool
misuse (ASI02). The model cannot be relied on to refuse, so the controls have
to sit outside it, on the path every call takes: least privilege per agent,
complete mediation, a human for the risky calls, and a record of everything.

## What it does

- **Agent identity**: static keys (only their SHA-256 is stored, compared in
  constant time) or short-lived signed tokens (HS256 JWS with `iss`, `aud`,
  `exp`, `nbf`, `iat`, a lifetime cap and key rotation by `kid`). Each identity
  has an agent id, an owner and scopes.
- **Policy**: an ordered JSON rule list. Default deny; an explicit deny beats
  any allow. Rules match agents or scopes, upstreams and tools (exact or
  `prefix_*`), and constrain arguments with a closed JSON Schema subset:
  `type`, `enum`, `pattern` (RE2), `minimum`/`maximum`,
  `minLength`/`maxLength`, `required`, `additionalProperties: false`, `items`,
  plus `x-path-prefix` for canonical file paths and `x-allowed-hosts` for
  URLs (allow rules only, so odd input fails closed). Unknown keywords are
  errors. Every decision names the rule that made it. The file is
  hot-reloaded atomically; an invalid file is rejected and the old policy stays.
- **Human approval**: rules marked `requires_approval` park the call. An
  administrator approves or denies it on a separate admin API. A grant is bound
  to the agent, the tool and the SHA-256 of the exact arguments, is single use
  and expires. The agent's request waits up to a configured time, or gets a
  "pending" error and retries the same call.
- **Rate limits and quotas**: token buckets (GCRA) per agent and per
  agent+tool, a daily call quota per agent, and a concurrency limit per
  upstream. Refusals are HTTP 429 with `Retry-After` (200 with `Retry-After`
  for clients in a 2025 session).
- **Upstream proxying**: agents see only the tools they may call, named
  `upstream.tool`. Calls are forwarded with a timeout, a response size limit
  and the upstream's credential added by the gateway; agent credentials are
  never forwarded and upstream URLs come only from configuration. Redirects are
  not followed.
- **Rug-pull detection**: each tool definition (name, title, description,
  schemas, annotations) is pinned by hash on first sight and persisted. A
  changed definition is quarantined, hidden and refused, until an administrator
  approves the new hash.
- **Output guarding**: per-rule redaction of credential shapes (AWS keys,
  GitHub and Slack tokens, private keys, bearer tokens, JWTs, custom RE2) and
  truncation to a byte budget, recorded in the audit log.
- **Tamper-evident audit log**: append-only JSONL, each record carrying the
  SHA-256 of the previous line, fsynced before the call proceeds (with group
  commit). `toolgate audit verify` finds any edit, deletion or reordering and
  names the line. Arguments are stored as an HMAC plus a redacted preview,
  never raw. If the log cannot be written, calls are refused.
- **Both MCP eras**: the current revision (2026-07-28: stateless, `_meta`
  and header checks, `server/discover`) and the handshake revisions
  (2025-11-25, 2025-06-18, 2025-03-26: `initialize`, `Mcp-Session-Id` bound to
  the agent, `DELETE`), on one endpoint, as both server and client. One
  JSON-RPC message per request (batches are refused, as the protocol requires
  since 2025-06-18), `Origin` validation against DNS rebinding, body limits,
  duplicate-key rejection, `x-mcp-header` mirroring and checks.

## Quick start

```console
$ ./examples/demo.sh        # builds both binaries, starts them, runs every scenario above
```

To run the pieces yourself:

```console
$ go build ./cmd/toolgate ./cmd/mcpfake
$ ./toolgate token new                                  # a key for an agent, and the hash for the config
$ MCPFAKE_SANDBOX=examples/sandbox MCPFAKE_TOKEN=upstream-secret-0123456789 \
    MCPFAKE_ADDR=127.0.0.1:19100 ./mcpfake &
$ export FAKE_UPSTREAM_TOKEN=upstream-secret-0123456789
$ TOOLGATE_CONFIG=examples/config.json TOOLGATE_POLICY=examples/policy.json \
    TOOLGATE_AUDIT_LOG=audit.jsonl TOOLGATE_AUDIT_KEY=$(openssl rand -hex 32) \
    TOOLGATE_ADMIN_TOKEN=$(openssl rand -hex 24) TOOLGATE_STATE_DIR=. ./toolgate
```

Then point any MCP client at `http://127.0.0.1:8080/mcp` with
`Authorization: Bearer <agent key>`. Configuration is documented in
[cmd/toolgate/main.go](cmd/toolgate/main.go); the config and policy formats in
[examples/config.json](examples/config.json) and
[examples/policy.json](examples/policy.json).

With Docker. The image holds both binaries, runs as `nonroot` on distroless,
and keeps the audit log and tool pins in `/data`. Here the fake upstream runs
as a second container; the config must name it (`http://mcpfake:19100/mcp`):

```console
$ docker build -t toolgate .
$ docker network create tgnet
$ docker run -d --network tgnet --network-alias mcpfake --entrypoint /mcpfake \
    -v "$PWD/examples/sandbox:/sandbox:ro" -e MCPFAKE_ADDR=0.0.0.0:19100 \
    -e MCPFAKE_SANDBOX=/sandbox -e MCPFAKE_TOKEN=upstream-secret-0123456789 toolgate
$ sed 's#127.0.0.1:19100#mcpfake:19100#' examples/config.json > /tmp/tg/config.json   # plus policy.json
$ docker run -d --network tgnet -p 127.0.0.1:8080:8080 -v /tmp/tg:/etc/toolgate:ro -v tgdata:/data \
    -e TOOLGATE_CONFIG=/etc/toolgate/config.json -e TOOLGATE_POLICY=/etc/toolgate/policy.json \
    -e TOOLGATE_AUDIT_LOG=/data/audit.jsonl -e TOOLGATE_STATE_DIR=/data \
    -e TOOLGATE_AUDIT_KEY=$(openssl rand -hex 32) -e TOOLGATE_ADMIN_TOKEN=$(openssl rand -hex 24) \
    -e FAKE_UPSTREAM_TOKEN=upstream-secret-0123456789 toolgate
```

## API

Agents (`TOOLGATE_ADDR`, default `127.0.0.1:8080`), `Authorization: Bearer <agent key or token>`:

| Endpoint | Purpose |
|---|---|
| `POST /mcp` | MCP over Streamable HTTP: `server/discover`, `tools/list`, `tools/call` (2026-07-28); `initialize`, `ping`, `tools/list`, `tools/call` in a session (2025-x). |
| `DELETE /mcp` | End a 2025-x session (`Mcp-Session-Id`). |
| `GET /healthz` | 200, or 503 when the audit log cannot be written. No auth. |

Administrators (`TOOLGATE_ADMIN_ADDR`, default `127.0.0.1:8081`), `Authorization: Bearer $TOOLGATE_ADMIN_TOKEN`:

| Endpoint | Purpose |
|---|---|
| `GET /admin/approvals`, `GET /admin/approvals/{id}` | Open approval requests with their exact arguments. |
| `POST /admin/approvals/{id}/approve` | `{"ttl_seconds":300,"note":"..."}` grants one use. |
| `POST /admin/approvals/{id}/deny` | `{"note":"..."}` refuses; retries of the same call are refused too. |
| `GET /admin/tools` | Pinned tool definitions; quarantined ones show the pending definition and hash. |
| `POST /admin/tools/{name}/approve` | `{"hash":"<pending_hash>"}` trusts the reviewed definition (compare-and-set). |
| `GET /admin/policy`, `POST /admin/policy/reload` | Policy hash; reload now (also on SIGHUP and when the file changes). |
| `GET /admin/audit/head` | Record count and head hash, to anchor the log elsewhere. |
| `GET /metrics` | Prometheus metrics. |

JSON-RPC errors from the gateway use codes outside the range JSON-RPC and MCP
reserve: `-31000` unauthenticated (401), `-31001` denied by policy, `-31002`
rate limited (429), `-31003` daily quota (429), `-31004` approval pending,
`-31005` approval denied, `-31006` tool quarantined, `-31007` upstream error
(502), `-31008` upstream timeout (504), `-31009` upstream busy (429), `-31010`
audit log unavailable (503). Protocol errors use the specification's codes:
`-32020` header mismatch, `-32022` unsupported version, `-32602` invalid params
or unknown tool. Clients in a 2025 session get every JSON-RPC error with
HTTP 200, as those revisions expect, and still get `Retry-After`.

Admin errors look like
`{"error":{"code":"not_found","message":"...","request_id":"..."}}`.

## How it is tested

| What | How |
|---|---|
| Policy decisions | Random policies (wildcards, scopes, deny rules with and without argument schemas, path prefixes) and random calls are checked against an independent, naive reference evaluator, for both `Evaluate` and the `tools/list` filter. Breaking the engine on purpose (ignoring scopes, dropping `*` upstream rules from the index, ignoring deny-rule schemas, hiding tools on conditional denies) makes it fail. |
| Rate limiting | Random schedules against an exact integer token-bucket reference; the GCRA limiter must admit exactly the same calls. |
| Audit log | Every single-byte flip is detected (by `Verify` or by the head hash); the log cut at every byte offset recovers exactly the complete records and the chain continues; edits, deletions, swaps and duplicates are reported at the right line; failed writes and fsyncs are injected. |
| End to end | A real gateway in front of a real MCP server over HTTP: filtered lists, credential injection, every denial path, rate limits, quotas, approval (including concurrent waiters, single use, denial), rug-pull quarantine and re-approval, redaction, truncation, upstream timeouts, oversized and malformed upstream replies, a down upstream, policy hot reload, signed tokens, legacy sessions and session hijack attempts, audit failure refusing calls. The binary itself is restarted with its state to check that pins and the audit chain survive. |
| Protocol | Every transport rule of both protocol eras over HTTP (headers, `_meta`, versions, Origin, Accept, body limit, batches, sessions); the client against a modern server, a hand-written 2025-era server with SSE, pagination and expiring sessions, and a set of misbehaving servers. |
| Parsers | Go fuzzing of the JSON-RPC decoder, the policy parser, the schema compiler and validator, the token verifier and the audit log reader. |
| Concurrency | The whole suite runs under the race detector in CI. |

```console
$ go test -race ./...                  # full suite, 96% statement coverage
$ go test -run=^$ -bench=. ./internal/...
```

## Performance

Apple M4 Max. Durability dominates: macOS `fsync` (`F_FULLFSYNC`) took 4 to
7 ms across runs, and an allowed call writes two fsynced audit records before
it returns. Ranges are over several runs; the in-memory steps are stable.

| Operation | Time |
|---|---|
| Policy decision, 200 rules, path constraint | 0.26 to 0.32 µs |
| Argument schema validation (4 properties, path and URL checks) | 1.3 µs |
| Static key authentication | 0.08 µs |
| Signed token verification | 2.3 to 2.6 µs |
| Rate limiter take | 0.10 to 0.12 µs |
| Audit append, one writer (fsync each) | 4.3 to 7.2 ms |
| Audit append, 16 writers (group commit) | 64 to 122 µs per record |
| `tools/call` end to end over HTTP, one agent | 8.6 to 17 ms |
| `tools/call` end to end, 64 concurrent callers | 0.8 to 1.2 ms per call |
| Denied `tools/call` end to end (one audit record) | 4.2 to 8.7 ms |

## Design

[docs/DESIGN.md](docs/DESIGN.md) covers the threat model, the order of checks,
the policy semantics, approvals, rug-pull detection, the audit log format, how
both MCP protocol eras are served, failure modes, limits and what would change
to run it as a fleet.

## Layout

```text
cmd/toolgate         gateway entry point, `audit verify` and `token` subcommands
cmd/mcpfake          a small MCP server to put behind the gateway
internal/gateway     the enforcement pipeline, upstream tool caching, admin API, configuration
internal/mcp         MCP over Streamable HTTP: dual-era server, client, header rules
internal/jsonrpc     strict JSON-RPC 2.0 decoding and encoding
internal/policy      policy parsing, evaluation, hot reload
internal/schema      the argument-constraint schema subset
internal/identity    static keys and signed tokens
internal/ratelimit   GCRA buckets, daily quotas, upstream concurrency
internal/approval    human approval requests and single-use grants
internal/pins        tool definition pinning and quarantine
internal/guard       output redaction, truncation and audit previews
internal/audit       hash-chained audit log and verification
internal/fakeserver  the tools behind cmd/mcpfake
internal/httpx       request IDs, logging, metrics, errors
internal/metrics     Prometheus text exposition
```

## License

MIT
