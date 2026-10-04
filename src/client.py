"""Fake MCP HTTP client + attacker receiver log.

No live network. Redirect map is a fixture.
"""

from __future__ import annotations

from pathlib import Path

from pin import Policy, RedirectDecision, decide_redirect, has_sensitive_forward

# Trusted MCP endpoint redirects. Values are absolute Location URLs.
REDIRECT_FIXTURES: dict[str, str] = {
    "https://mcp.example.com/v1/session": "https://attacker.example/collect",
    "https://mcp.example.com/v1/ok": "https://mcp.example.com/v1/final",
}


def clear_log(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def log_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip()]


def append_receiver(path: Path, origin: str, headers: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        hdr = ",".join(headers) if headers else "-"
        f.write(f"{origin}|{hdr}\n")


class RedirectClient:
    """Simulates one hop: GET request_url, see Location, apply policy."""

    def __init__(self, receiver_log: Path, policy: Policy) -> None:
        self.receiver_log = receiver_log
        self.policy = policy

    def request(
        self,
        request_url: str,
        headers: dict[str, str] | None = None,
    ) -> dict:
        headers = headers or {
            "X-API-Key": "secret-key-9f3a",
            "mcp-session-id": "sess-abc",
            "Authorization": "Bearer tok-should-drop-cross",
        }
        location = REDIRECT_FIXTURES.get(request_url)
        if location is None:
            return {
                "ok": True,
                "reason": "no_redirect",
                "leaked": False,
                "lines": len(log_lines(self.receiver_log)),
                "decision": None,
            }

        decision: RedirectDecision = decide_redirect(
            request_url, location, headers, self.policy
        )
        if decision.allowed:
            append_receiver(
                self.receiver_log,
                decision.location_origin,
                decision.forwarded_headers,
            )
        leaked = has_sensitive_forward(decision) and (
            decision.location_origin != decision.request_origin
        )
        return {
            "ok": decision.allowed,
            "reason": decision.reason,
            "leaked": leaked,
            "location": decision.location,
            "lines": len(log_lines(self.receiver_log)),
            "forwarded": list(decision.forwarded_headers),
            "decision": decision,
        }
