# AGENTS.md - RedirectOriginPin

Cold-start handoff for a coding agent with no prior context.

## Claim proved

An MCP-style HTTP client with `follow_all` redirect policy forwards custom headers (`X-API-Key`) to a cross-origin Location target. The same request under `same_origin` is denied with `blocked_cross_origin` and writes zero attacker receiver lines. A same-origin Location is still followed under `same_origin`, so the pin is not "never redirect."

Evidence from `bash demo.sh`:

1. PATH A: `follow_all` on `https://mcp.example.com/v1/session` → Location `https://attacker.example/collect` → 1 attacker log line containing `x-api-key:secret-key-9f3a`. Reason `followed_cross_origin`.
2. PATH B: `same_origin` on the same URL → 0 attacker lines. Reason `blocked_cross_origin`.
3. PATH C: `same_origin` on `https://mcp.example.com/v1/ok` → Location `https://mcp.example.com/v1/final` → 1 peer log line with the key; no attacker origin. Reason `followed_same_origin`.

## Status: real vs stubbed

Real:

- `RedirectDecision` + `decide_redirect` origin compare and header forward rules
- Fake `RedirectClient` with fixture redirect map and append-only receiver log
- Bare `Authorization` dropped on cross-origin (matches platform fetch behavior named in the advisories)
- Self-proving `demo.sh` with exit codes

Stubbed / not built:

- Live HTTP client or MCP SDK transport patch
- Multi-hop redirect chains
- DNS / private-IP classification (see FetchUrlFence)
- OAuth issuer or protected-resource field pins (see IssuerPin / ResourcePin)
- Hivemind OS or Workflow Core integration

## Data shape (with paths)

Primary type: `RedirectDecision` in `src/pin.py`.

| Field | Meaning |
| --- | --- |
| `allowed` | may the client follow Location |
| `reason` | `followed_cross_origin` \| `followed_same_origin` \| `blocked_cross_origin` \| `blocked_error_policy` \| `no_redirect` |
| `request_origin` | scheme://host[:port] of the original request |
| `location_origin` | scheme://host[:port] of Location |
| `location` | full Location URL |
| `forwarded_headers` | `name:value` tuples that would be sent on the next hop |

Side-effect oracle: `data/attacker_receiver.log` (one `origin|headers` line per followed hop).

Redirect fixtures: `REDIRECT_FIXTURES` in `src/client.py`.

## Repo map

| Path | Role |
| --- | --- |
| `src/pin.py` | `RedirectDecision`, `decide_redirect`, `origin_of` |
| `src/client.py` | Fake client + fixtures + receiver log helpers |
| `src/__init__.py` | package marker |
| `demo.sh` | proof runner |
| `README.md` | short human summary |
| `AGENTS.md` | this file |
| `requirements.txt` | notes stdlib-only |
| `.gitignore` | ignores `data/`, caches |
| `LICENSE` | MIT |

## Setup / run / verify (fresh clone)

```bash
git clone https://github.com/ideator-labs/redirectoriginpin.git
cd redirectoriginpin
bash demo.sh
```

Needs Python 3.10+ on PATH. No pip install.

Expected pass (abridged):

```
PATH A (follow_all cross-origin): PASS
PATH B (same_origin cross-origin): PASS
PATH C (same_origin same-origin hop): PASS
SUMMARY: 3 passed, 0 failed
ALL CLAIMS PASSED
```

Failure looks like: any PATH line ends with `FAIL`, or SUMMARY shows non-zero failed, or process exit code is non-zero.

Break check (optional): edit PATH B expected string in `demo.sh` so the assertion mismatches; `bash demo.sh` must exit non-zero; restore the file.

## Design decisions

- Named the data shape (`RedirectDecision`) before the client wrapper.
- Fixture redirects only. The claim is about origin policy + header forward, not DNS or sockets.
- Drop bare `Authorization` on cross-origin under `follow_all` so PATH A isolates the custom-header trap the advisories describe.
- `same_origin` still allows same-origin hops (PATH C) so the pin is not a blunt disable.

## Known limits

- Single hop only.
- Hostname compare is string origin equality after lowercasing; no IDNA edge cases covered.
- Not wired into real `@modelcontextprotocol/sdk` or `mcp` transports.
- Does not detect the `redirectPolicy: 'follow'` escape hatch in app code; that is a lint follow-up.

## Prioritized next steps (done-when)

1. **httpx/fetch wrapper.** Done when a thin adapter calls `decide_redirect` before each Location hop in a real httpx client test and PATH A/B still pass against a local redirect server.
2. **Escape-hatch lint.** Done when a script flags `redirectPolicy: 'follow'` / `follow_redirects=True` on MCP transport construction in a sample tree and exits non-zero on hit.
3. **Hivemind plug.** Done when Hivemind's MCP client path can set policy=`same_origin` via config and a harness test asserts zero cross-origin custom-header forwards.
4. **Workflow Core plug.** Done when an HTTP activity step can refuse cross-origin redirects before resume and a unit test shows the workflow records `blocked_cross_origin`.

## Working rules

- Keep demo.sh as the real artifact. Do not declare done from unit tests alone.
- No em-dashes in prose. Short plain sentences.
- Stdlib only unless a next step explicitly adds a dependency.
- Verify on a fresh clone before publish.

## Sources (checked URLs only)

- https://al-ice.ai/posts/2026/10/mcp-sdk-october-advisories-cross-origin-redirect-task-session-scanner-gap/
- GHSA-6prh-2h8m-c8cw (modelcontextprotocol/typescript-sdk, verified via gh API 2026-10-04)
- GHSA-5h93-6whr-6q8j (modelcontextprotocol/python-sdk, verified via gh API 2026-10-04)
