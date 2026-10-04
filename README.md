# RedirectOriginPin

Same-origin redirect pin for MCP-style HTTP clients.

See [AGENTS.md](./AGENTS.md) for the full handoff (claim, data shape, verify steps, limits).

## What it proves

An unguarded `follow_all` policy re-sends custom headers (`X-API-Key`) to a cross-origin redirect target. A `same_origin` policy blocks that hop with `blocked_cross_origin` and writes zero attacker log lines. The same policy still follows a same-origin Location.

This matches the Oct 2 MCP SDK advisories (GHSA-6prh-2h8m-c8cw, GHSA-5h93-6whr-6q8j): platform fetch already drops bare `Authorization` across origins, but custom authority headers were forwarded.

## Run

```bash
bash demo.sh
```

Needs Python 3.10+. No pip install. No live network.

## Limits

Fixture redirects only. Not a drop-in SDK patch. Does not cover DNS rebinding or private-IP SSRF (see FetchUrlFence). Does not validate OAuth issuer/resource fields (see IssuerPin / ResourcePin).
