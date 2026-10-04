"""Same-origin redirect pin for MCP-style HTTP clients.

Data shape: RedirectDecision.
policy is one of follow_all | same_origin | error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

Policy = Literal["follow_all", "same_origin", "error"]

SENSITIVE_CUSTOM = ("x-api-key", "mcp-session-id", "client_secret")


@dataclass(frozen=True)
class RedirectDecision:
    allowed: bool
    reason: str
    request_origin: str
    location_origin: str
    location: str
    forwarded_headers: tuple[str, ...] = field(default_factory=tuple)


def origin_of(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        raise ValueError(f"bad url: {url!r}")
    return f"{p.scheme.lower()}://{p.netloc.lower()}"


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def decide_redirect(
    request_url: str,
    location: str,
    headers: dict[str, str],
    policy: Policy,
) -> RedirectDecision:
    """Decide whether to follow Location and which headers to forward.

    follow_all: always follow; forward all headers including custom secrets.
    same_origin: follow only when Location origin matches request origin.
    error: never follow redirects.
    """
    req_origin = origin_of(request_url)
    loc_origin = origin_of(location)
    norm = _normalize_headers(headers)

    if policy == "error":
        return RedirectDecision(
            allowed=False,
            reason="blocked_error_policy",
            request_origin=req_origin,
            location_origin=loc_origin,
            location=location,
            forwarded_headers=(),
        )

    if policy == "same_origin" and loc_origin != req_origin:
        return RedirectDecision(
            allowed=False,
            reason="blocked_cross_origin",
            request_origin=req_origin,
            location_origin=loc_origin,
            location=location,
            forwarded_headers=(),
        )

    # Platform fetch already drops bare Authorization across origins.
    # Custom authority headers are the trap the Oct 2 advisories name.
    forwarded: list[str] = []
    cross = loc_origin != req_origin
    for name, value in norm.items():
        if cross and name == "authorization":
            continue
        forwarded.append(f"{name}:{value}")

    reason = "followed_cross_origin" if cross else "followed_same_origin"
    return RedirectDecision(
        allowed=True,
        reason=reason,
        request_origin=req_origin,
        location_origin=loc_origin,
        location=location,
        forwarded_headers=tuple(forwarded),
    )


def has_sensitive_forward(decision: RedirectDecision) -> bool:
    for item in decision.forwarded_headers:
        name = item.split(":", 1)[0]
        if name in SENSITIVE_CUSTOM:
            return True
    return False
