#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src"

LOG="$ROOT/data/attacker_receiver.log"
mkdir -p "$ROOT/data"
: > "$LOG"

pass_count=0
fail_count=0

echo "=== RedirectOriginPin demo ==="
echo "Same-origin redirect pin for MCP-style HTTP clients."
echo "No live network; redirect hops are fixtures."
echo

# PATH A: follow_all leaks X-API-Key to cross-origin attacker
echo "PATH A (follow_all cross-origin): BEFORE lines=0"
a_out=$(python3 - <<'PY'
from pathlib import Path
from client import RedirectClient, clear_log, log_lines
log = Path("data/attacker_receiver.log")
clear_log(log)
c = RedirectClient(log, policy="follow_all")
r = c.request("https://mcp.example.com/v1/session")
lines = log_lines(log)
leaked = any("x-api-key:secret-key-9f3a" in ln for ln in lines)
print(f"ok={r['ok']} reason={r['reason']} leaked={leaked} lines={len(lines)}")
PY
)
echo "PATH A AFTER=$a_out"
if [[ "$a_out" == "ok=True reason=followed_cross_origin leaked=True lines=1" ]]; then
  echo "PATH A (follow_all cross-origin): PASS"
  pass_count=$((pass_count + 1))
else
  echo "PATH A (follow_all cross-origin): FAIL"
  fail_count=$((fail_count + 1))
fi
echo

# PATH B: same_origin blocks cross-origin; zero attacker lines
echo "PATH B (same_origin cross-origin): BEFORE lines=0"
b_out=$(python3 - <<'PY'
from pathlib import Path
from client import RedirectClient, clear_log, log_lines
log = Path("data/attacker_receiver.log")
clear_log(log)
c = RedirectClient(log, policy="same_origin")
r = c.request("https://mcp.example.com/v1/session")
lines = log_lines(log)
leaked = any("x-api-key:" in ln for ln in lines)
print(f"ok={r['ok']} reason={r['reason']} leaked={leaked} lines={len(lines)}")
PY
)
echo "PATH B AFTER=$b_out"
if [[ "$b_out" == "ok=False reason=blocked_cross_origin leaked=False lines=0" ]]; then
  echo "PATH B (same_origin cross-origin): PASS"
  pass_count=$((pass_count + 1))
else
  echo "PATH B (same_origin cross-origin): FAIL"
  fail_count=$((fail_count + 1))
fi
echo

# PATH C: same_origin still follows same-origin Location
echo "PATH C (same_origin same-origin hop): BEFORE lines=0"
c_out=$(python3 - <<'PY'
from pathlib import Path
from client import RedirectClient, clear_log, log_lines
log = Path("data/attacker_receiver.log")
clear_log(log)
c = RedirectClient(log, policy="same_origin")
r = c.request("https://mcp.example.com/v1/ok")
lines = log_lines(log)
has_key = any("x-api-key:secret-key-9f3a" in ln for ln in lines)
cross = any("attacker.example" in ln for ln in lines)
print(f"ok={r['ok']} reason={r['reason']} has_key={has_key} cross={cross} lines={len(lines)}")
PY
)
echo "PATH C AFTER=$c_out"
if [[ "$c_out" == "ok=True reason=followed_same_origin has_key=True cross=False lines=1" ]]; then
  echo "PATH C (same_origin same-origin hop): PASS"
  pass_count=$((pass_count + 1))
else
  echo "PATH C (same_origin same-origin hop): FAIL"
  fail_count=$((fail_count + 1))
fi
echo

echo "SUMMARY: $pass_count passed, $fail_count failed"
if [[ "$fail_count" -ne 0 || "$pass_count" -ne 3 ]]; then
  exit 1
fi
echo "ALL CLAIMS PASSED"
exit 0
