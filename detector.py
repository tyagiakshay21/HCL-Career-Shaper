"""Detect credential-like values exposed in readable, plain HTTP traffic.

Run ``python detector.py path/to/http-stream.txt`` to inspect a Wireshark HTTP
Stream export, or run ``python detector.py --serve`` to start the demo server
and dashboard on http://localhost:5000.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, render_template_string, request


SECRET_PATTERNS = {
    "password": re.compile(r"(?:^|[?&\s])password=([^&\s]+)", re.IGNORECASE),
    "api_key": re.compile(r"(?:^|[?&\s])api_key=([^&\s]+)", re.IGNORECASE),
    "token": re.compile(r"(?:^|[?&\s])token=([^&\s]+)", re.IGNORECASE),
}

BASE_DIR = Path(__file__).resolve().parent
FINDINGS_FILE = Path(os.environ.get("FINDINGS_FILE", BASE_DIR / "findings.json"))
MAX_FINDINGS = 50
app = Flask(__name__)


def find_secrets(text: str) -> list[str]:
    """Return matched field names; never return or store captured values."""
    return [name for name, pattern in SECRET_PATTERNS.items() if pattern.search(text)]


def is_plain_http(text: str) -> bool:
    """Recognize readable HTTP request/response lines from a stream export."""
    first_line = text.lstrip().splitlines()[0] if text.strip() else ""
    if re.match(r"(?i)^https://", first_line):
        return False
    return bool(
        re.match(r"^[A-Z]+\s+\S+\s+HTTP/1\.[01](?:\s|$)", first_line)
        or re.match(r"^HTTP/1\.[01]\s+\d{3}(?:\s|$)", first_line)
    )


def detect_exposure(text: str, transport: str) -> dict[str, Any]:
    """Flag a credential pattern only when the supplied transport is HTTP."""
    matches = find_secrets(text)
    insecure = transport.strip().lower() == "http"
    return {
        "alert": bool(matches and insecure),
        "reason": "Credential exposed over insecure HTTP" if matches and insecure else "No insecure credential exposure detected",
        "matches": matches,
    }


def _read_findings() -> list[dict[str, str]]:
    try:
        with FINDINGS_FILE.open("r", encoding="utf-8") as handle:
            rows = json.load(handle)
        if not isinstance(rows, list):
            return []
        return [row for row in rows if isinstance(row, dict) and {"time", "summary", "severity"} <= row.keys()]
    except (OSError, json.JSONDecodeError):
        return []


def save_finding(summary: str, severity: str = "Info") -> None:
    """Persist only a sanitized summary, retaining the latest 50 findings."""
    rows = _read_findings()
    rows.append({
        "time": dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "summary": summary,
        "severity": severity,
    })
    rows = rows[-MAX_FINDINGS:]
    FINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Replace atomically so a dashboard refresh never reads a half-written file.
    fd, temp_name = tempfile.mkstemp(prefix="findings-", suffix=".tmp", dir=FINDINGS_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=2)
        os.replace(temp_name, FINDINGS_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


DASH_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="10"><title>Plaintext HTTP Lab · Findings</title>
  <style>
    :root{color-scheme:dark;--bg:#0b1220;--panel:#111c2e;--line:#26364d;--muted:#91a2ba;--text:#edf4ff;--blue:#60a5fa}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 20% -10%,#183353 0,transparent 45%),var(--bg);color:var(--text);font:15px/1.5 Inter,Segoe UI,Arial,sans-serif}
    main{max-width:1060px;margin:0 auto;padding:54px 24px}.eyebrow{color:#8fc6ff;text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:700}
    h1{font-size:clamp(30px,5vw,46px);letter-spacing:-.04em;margin:10px 0}.intro{color:var(--muted);max-width:650px;margin:0}
    .panel{margin-top:32px;padding:24px;background:rgba(17,28,46,.94);border:1px solid var(--line);border-radius:18px;box-shadow:0 20px 60px #02061766}
    .panel-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}.panel-head h2{margin:0;font-size:19px}.count{border:1px solid var(--line);border-radius:999px;color:var(--muted);padding:5px 11px;font-size:12px}
    .table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:560px}th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;padding:12px;border-bottom:1px solid var(--line)}td{padding:15px 12px;border-bottom:1px solid #26364d99}tbody tr:last-child td{border-bottom:0}.time{font-variant-numeric:tabular-nums;color:#bdcce0;white-space:nowrap}
    .badge{display:inline-flex;align-items:center;gap:8px;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700}.badge:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}.critical,.high{color:#ffc1bc;background:#5c252a}.medium{color:#ffd28a;background:#573c16}.low,.info{color:#bdc9d8;background:#344154}
    .empty{padding:34px 20px;text-align:center;border:1px dashed #35465e;border-radius:12px;color:var(--muted)}.empty strong{display:block;color:var(--text);font-size:16px;margin-bottom:4px}
    footer{margin-top:16px;color:#71839b;font-size:12px}
    @media(max-width:600px){main{padding:34px 16px}.panel{padding:18px}.panel-head{align-items:flex-start;flex-direction:column}table{min-width:0;table-layout:fixed}th:nth-child(1),td:nth-child(1){width:35%}th:nth-child(2),td:nth-child(2){width:43%}th:nth-child(3),td:nth-child(3){width:22%}.time{white-space:normal}}
  </style>
</head>
<body><main>
  <div class="eyebrow">Plaintext HTTP lab · Monitor</div>
  <h1>Security findings</h1>
  <p class="intro">Credential exposure alerts detected from readable HTTP traffic. Values are masked at detection and never saved here. This page refreshes every 10 seconds.</p>
  <section class="panel" aria-labelledby="findings-title">
    <div class="panel-head"><h2 id="findings-title">Recent detections</h2><span class="count">{{ rows|length }} / 50 findings</span></div>
    {% if rows %}<div class="table-wrap"><table><thead><tr><th>Detected</th><th>Finding</th><th>Severity</th></tr></thead><tbody>
      {% for r in rows %}<tr><td class="time">{{ r.time }}</td><td>{{ r.summary }}</td><td><span class="badge {{ r.severity|lower }}">{{ r.severity }}</span></td></tr>{% endfor %}
    </tbody></table></div>{% else %}<div class="empty"><strong>No findings yet</strong>Send a clearly fake credential to the local HTTP demo endpoint to create a finding.</div>{% endif %}
  </section>
  <footer>Demo only · Use fake values · Findings are stored locally in findings.json</footer>
</main></body></html>"""


@app.get("/")
def home() -> str:
    return '<h1>Plaintext HTTP lab is running</h1><p><a href="/dashboard">Open the findings dashboard</a></p>'


@app.get("/dashboard")
def dashboard() -> str:
    rows = list(reversed(_read_findings()))
    return render_template_string(DASH_HTML, rows=rows)


@app.post("/login")
def login() -> tuple[str, int]:
    # This endpoint deliberately uses plain HTTP for the local lab demonstration.
    payload = "&".join(f"{key}={value}" for key, value in request.form.items())
    result = detect_exposure(payload, "http" if not request.is_secure else "https")
    if result["alert"]:
        labels = ", ".join(result["matches"])
        save_finding(f"Credential field(s) {labels} exposed over insecure HTTP", "High")
        app.logger.warning("Credential exposure detected over HTTP (fields: %s); values omitted", labels)
    return "Lab request received; submitted values are not echoed or stored.", 200


def analyze_file(filename: str) -> int:
    path = Path(filename)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        print(f"Could not read {path}: {exc}")
        return 2

    transport = "http" if is_plain_http(text) else "unknown"
    result = detect_exposure(text, transport)
    if result["alert"]:
        for name in result["matches"]:
            print(f"EXPOSURE: credential pattern '{name}' found over plain HTTP (insecure transport)")
        save_finding(f"Credential field(s) {', '.join(result['matches'])} exposed over insecure HTTP", "High")
        return 1
    if result["matches"]:
        print("Credential-like field found, but the stream does not show plain HTTP - not flagged")
    else:
        print(f"No exposure found in {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect fake credential exposure in a readable HTTP stream.")
    parser.add_argument("stream", nargs="?", help="Wireshark Follow HTTP Stream text export")
    parser.add_argument("--serve", action="store_true", help="run the local demo server and dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="bind address for --serve (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="port for --serve (default: 5000)")
    args = parser.parse_args()
    if args.serve:
        app.run(host=args.host, port=args.port, debug=False)
        return 0
    if args.stream:
        return analyze_file(args.stream)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
