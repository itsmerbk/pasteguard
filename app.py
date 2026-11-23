import base64
import hashlib
import json
import math
import re
import sqlite3
import subprocess
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 8787
DB_PATH = Path("pasteguard.db")

db_lock = threading.Lock()
sse_clients = []
sse_lock = threading.Lock()
auto_shield_enabled = True

SECRET_PATTERNS = [
    ("GitHub PAT", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("OpenAI / Anthropic Key", re.compile(r"\b(sk-[A-Za-z0-9\-_]{20,})\b")),
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("JWT Bearer Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Private Key PEM", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

SAMPLE_LEAKS = [
    "GITHUB_TOKEN=ghp_9xK2mP7vL4qR8nW1zT5yB3cF6hJ0dS4aE8uI",
    "OPENAI_API_KEY=sk-proj-84f9a2c1e7b04d6f9a3c5e1b7d2f8a4c6e0b9d1f",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
]
leak_idx = 0

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with db_lock:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_hash TEXT UNIQUE,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                secret_type TEXT,
                source_app TEXT DEFAULT 'macOS',
                pinned INTEGER DEFAULT 0,
                copy_count INTEGER DEFAULT 1,
                updated_at TEXT NOT NULL
            )
        """)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(clips)").fetchall()]
        if "source_app" not in cols:
            conn.execute("ALTER TABLE clips ADD COLUMN source_app TEXT DEFAULT 'macOS'")
        conn.commit()
    return conn

conn = init_db()

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {ch: data.count(ch) for ch in set(data)}
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def detect_secret(text: str):
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return label
    lines = text.strip().splitlines()
    if len(lines) <= 2:
        for raw_tok in text.split():
            tok = raw_tok.split("=")[-1].strip("\"'`,;")
            if 32 <= len(tok) <= 128 and not tok.startswith(("http://", "https://", "/")):
                if shannon_entropy(tok) >= 4.4:
                    return "High-Entropy API Token"
    return None

def redact_secret(text: str) -> str:
    redacted = text
    for _, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: m.group(0)[:7] + "•" * 12 + m.group(0)[-4:], redacted)
    if redacted == text:
        out = []
        for raw_tok in text.split(" "):
            if "=" in raw_tok:
                k, v = raw_tok.split("=", 1)
                if len(v) >= 24:
                    out.append(f"{k}={v[:6]}{'•'*10}{v[-3:]}")
                    continue
            if len(raw_tok) >= 32 and shannon_entropy(raw_tok) >= 4.4:
                out.append(raw_tok[:6] + "•" * 10 + raw_tok[-4:])
            else:
                out.append(raw_tok)
        redacted = " ".join(out)
    return redacted

def classify_content(text: str):
    stripped = text.strip()
    secret = detect_secret(stripped)
    if secret:
        return "SECRET", secret
    if stripped.startswith(("http://", "https://")) and "\n" not in stripped:
        return "URL", None
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            json.loads(stripped)
            return "JSON", None
        except Exception:
            pass
    cmd_prefixes = ("git ", "python", "npm ", "brew ", "docker ", "curl ", "cd ", "ls ", "gh ", "javac ", "java ", "pip ")
    if stripped.startswith(cmd_prefixes) and len(stripped.splitlines()) <= 4:
        return "COMMAND", None
    code_markers = ("def ", "class ", "import ", "from ", "const ", "function ", "public static", "#include", "=>", "return ")
    if any(m in stripped for m in code_markers) or ("\n" in stripped and ("{" in stripped or ":" in stripped)):
        return "CODE", None
    return "TEXT", None

def get_macos_clipboard() -> str:
    try:
        proc = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=1.0)
        return proc.stdout if proc.returncode == 0 else ""
    except Exception:
        return ""

def set_macos_clipboard(text: str) -> None:
    subprocess.run(["pbcopy"], input=text, text=True, check=False)

def get_frontmost_app() -> str:
    try:
        script = 'tell application "System Events" to get name of first application process whose frontmost is true'
        proc = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=0.6)
        name = proc.stdout.strip()
        return name if name else "macOS"
    except Exception:
        return "macOS"

def broadcast_sse(event_payload: dict) -> None:
    msg = f"data: {json.dumps(event_payload)}\n\n".encode("utf-8")
    with sse_lock:
        dead = []
        for wfile in sse_clients:
            try:
                wfile.write(msg)
                wfile.flush()
            except Exception:
                dead.append(wfile)
        for d in dead:
            sse_clients.remove(d)

def save_clip(text: str, source_app: str = "macOS"):
    if not text or not text.strip():
        return None
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    category, secret_type = classify_content(text)
    now = datetime.now().strftime("%H:%M:%S")
    with db_lock:
        existing = conn.execute("SELECT id, copy_count FROM clips WHERE content_hash = ?", (digest,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE clips SET copy_count = ?, updated_at = ?, source_app = ? WHERE id = ?",
                (existing["copy_count"] + 1, now, source_app, existing["id"]),
            )
            row_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO clips (content_hash, content, category, secret_type, source_app, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (digest, text, category, secret_type, source_app, now),
            )
            row_id = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM clips WHERE id = ?", (row_id,)).fetchone()
    item = dict(row)
    item["redacted"] = redact_secret(item["content"]) if item["secret_type"] else None
    item["shielded"] = False
    return item

def clipboard_watcher() -> None:
    last_hash = ""
    while True:
        current = get_macos_clipboard()
        if current and current.strip():
            h = hashlib.sha256(current.encode("utf-8")).hexdigest()
            if h != last_hash:
                source_app = get_frontmost_app()
                item = save_clip(current, source_app=source_app)
                if item:
                    if item["category"] == "SECRET" and auto_shield_enabled and item["redacted"]:
                        set_macos_clipboard(item["redacted"])
                        last_hash = hashlib.sha256(item["redacted"].encode("utf-8")).hexdigest()
                        item["shielded"] = True
                    else:
                        last_hash = h
                    broadcast_sse({"type": "clip_update", "item": item})
        time.sleep(0.35)

def transform_text(text: str, mode: str) -> str:
    if mode == "redact":
        return redact_secret(text)
    if mode == "json_pretty":
        return json.dumps(json.loads(text), indent=2)
    if mode == "b64_encode":
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")
    if mode == "b64_decode":
        return base64.b64decode(text.strip()).decode("utf-8", errors="replace")
    if mode == "extract_urls":
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        return "\n".join(dict.fromkeys(urls)) if urls else "No URLs found in snippet."
    if mode == "curl_to_py":
        url_match = re.search(r"https?://[^\s\"']+", text)
        url = url_match.group(0) if url_match else "https://api.example.com/v1/resource"
        return f'import requests\n\nresponse = requests.get("{url}", timeout=10)\nprint(response.status_code, response.json())'
    return text

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PasteGuard Pro — Real-Time macOS Clipboard &amp; Secret Firewall</title>
  <style>
    :root {
      --bg: #050811;
      --surface: rgba(15, 22, 38, 0.82);
      --surface-solid: #0f1626;
      --surface-elevated: #162036;
      --border: rgba(148, 163, 184, 0.14);
      --border-bright: rgba(56, 189, 248, 0.45);
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --indigo: #818cf8;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #f43f5e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", sans-serif;
      background:
        radial-gradient(circle at 12% 8%, rgba(56, 189, 248, 0.12), transparent 34%),
        radial-gradient(circle at 88% 12%, rgba(129, 140, 248, 0.11), transparent 36%),
        var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 20px 26px;
    }
    .shell { max-width: 1380px; margin: 0 auto; }

    /* Top Command Header */
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
      background: var(--surface);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px 20px;
      margin-bottom: 18px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .logo {
      width: 40px; height: 40px; border-radius: 11px;
      background: linear-gradient(135deg, #0284c7, #6366f1);
      display: grid; place-items: center;
      box-shadow: 0 0 22px rgba(56, 189, 248, 0.35);
    }
    .brand h1 { font-size: 1.25rem; font-weight: 700; letter-spacing: -0.02em; display: flex; align-items: center; gap: 8px; }
    .pro-tag {
      font-size: 0.68rem; font-weight: 800; letter-spacing: 0.06em;
      padding: 2px 8px; border-radius: 999px;
      background: linear-gradient(135deg, rgba(56,189,248,0.22), rgba(129,140,248,0.22));
      border: 1px solid var(--border-bright); color: var(--accent);
    }
    .brand-sub { font-size: 0.8rem; color: var(--muted); margin-top: 2px; }

    .top-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .shield-box {
      display: flex; align-items: center; gap: 10px;
      background: var(--surface-elevated);
      border: 1px solid var(--border);
      padding: 7px 13px; border-radius: 11px;
      font-size: 0.82rem; font-weight: 600;
    }
    .switch { position: relative; width: 38px; height: 21px; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; inset: 0;
      background: #334155; border-radius: 999px; transition: 0.25s;
    }
    .slider:before {
      content: ""; position: absolute; height: 15px; width: 15px; left: 3px; bottom: 3px;
      background: white; border-radius: 50%; transition: 0.25s;
    }
    input:checked + .slider { background: var(--green); box-shadow: 0 0 12px rgba(16,185,129,0.5); }
    input:checked + .slider:before { transform: translateX(17px); }

    .sim-btn {
      background: rgba(244, 63, 94, 0.14);
      border: 1px solid rgba(244, 63, 94, 0.45);
      color: #fda4af;
      padding: 8px 14px; border-radius: 11px;
      font-size: 0.82rem; font-weight: 600; cursor: pointer;
      transition: all 0.15s ease;
    }
    .sim-btn:hover { background: rgba(244, 63, 94, 0.24); transform: translateY(-1px); }

    .live-badge {
      display: inline-flex; align-items: center; gap: 7px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: var(--green); padding: 7px 13px; border-radius: 11px;
      font-size: 0.8rem; font-weight: 700;
    }
    .pulse-dot {
      width: 8px; height: 8px; border-radius: 50%; background: var(--green);
      box-shadow: 0 0 10px var(--green); animation: blink 1.3s infinite;
    }
    @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

    /* KPI Strip */
    .kpi-grid {
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 18px;
    }
    .kpi {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; padding: 15px 18px; position: relative; overflow: hidden;
    }
    .kpi::after {
      content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, var(--accent), transparent);
    }
    .kpi.danger::after { background: linear-gradient(90deg, var(--red), transparent); }
    .kpi.safe::after { background: linear-gradient(90deg, var(--green), transparent); }
    .kpi-title { font-size: 0.74rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
    .kpi-num { font-size: 1.65rem; font-weight: 800; margin-top: 5px; letter-spacing: -0.02em; }
    .kpi-foot { font-size: 0.76rem; color: var(--muted); margin-top: 3px; }

    /* Main Split Layout */
    .workspace { display: grid; grid-template-columns: 1.28fr 1fr; gap: 18px; align-items: start; }
    .panel {
      background: var(--surface); backdrop-filter: blur(14px);
      border: 1px solid var(--border); border-radius: 16px; padding: 18px;
    }

    .filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
    .search-box {
      width: 100%; background: var(--surface-elevated); border: 1px solid var(--border);
      border-radius: 11px; padding: 10px 14px; color: var(--text); font-size: 0.9rem;
      margin-bottom: 10px; outline: none;
    }
    .search-box:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(56,189,248,0.12); }

    .pill {
      background: var(--surface-elevated); border: 1px solid var(--border);
      color: var(--muted); padding: 6px 12px; border-radius: 9px;
      font-size: 0.79rem; font-weight: 600; cursor: pointer;
    }
    .pill.active { background: rgba(56,189,248,0.16); border-color: var(--accent); color: var(--accent); }
    .pill.purge { margin-left: auto; color: #fda4af; border-color: rgba(244,63,94,0.35); background: rgba(244,63,94,0.1); }

    .feed-list { display: flex; flex-direction: column; gap: 10px; max-height: 610px; overflow-y: auto; padding-right: 4px; }
    .clip-card {
      background: var(--surface-solid); border: 1px solid var(--border);
      border-radius: 12px; padding: 13px 15px; cursor: pointer;
      transition: all 0.16s ease;
    }
    .clip-card:hover { border-color: rgba(148,163,184,0.35); transform: translateX(2px); }
    .clip-card.selected { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
    .clip-card.secret {
      border-color: rgba(244, 63, 94, 0.55);
      background: linear-gradient(135deg, rgba(244,63,94,0.1), var(--surface-solid) 65%);
    }

    .card-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; }
    .tag-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .badge {
      font-size: 0.71rem; font-weight: 700; padding: 2px 8px; border-radius: 6px;
      background: var(--surface-elevated); border: 1px solid var(--border); color: var(--accent);
    }
    .badge.SECRET { background: rgba(244,63,94,0.2); border-color: var(--red); color: #fda4af; }
    .badge.CODE { color: var(--indigo); }
    .badge.COMMAND { color: var(--green); }
    .badge.URL { color: var(--amber); }
    .badge.app { color: #cbd5e1; font-weight: 500; }
    .shielded-tag { font-size: 0.7rem; color: var(--green); font-weight: 700; }

    .card-btns { display: flex; gap: 5px; }
    .mini-btn {
      background: var(--surface-elevated); border: 1px solid var(--border);
      color: var(--text); padding: 4px 9px; border-radius: 6px;
      font-size: 0.74rem; font-weight: 600; cursor: pointer;
    }
    .mini-btn:hover { border-color: var(--accent); }
    .mini-btn.red { border-color: rgba(244,63,94,0.5); color: #fda4af; }

    .snippet-preview {
      font-family: "SF Mono", Menlo, monospace; font-size: 0.8rem;
      color: #cbd5e1; white-space: pre-wrap; word-break: break-word;
      max-height: 76px; overflow: hidden;
    }

    /* Right Inspector Panel */
    .inspector-head {
      display: flex; justify-content: space-between; align-items: center;
      padding-bottom: 12px; border-bottom: 1px solid var(--border); margin-bottom: 14px;
    }
    .inspector-title { font-size: 0.98rem; font-weight: 700; }
    .transform-grid {
      display: grid; grid-template-columns: repeat(3, 1fr); gap: 7px; margin-bottom: 14px;
    }
    .tx-btn {
      background: var(--surface-elevated); border: 1px solid var(--border);
      color: var(--text); padding: 8px 10px; border-radius: 9px;
      font-size: 0.77rem; font-weight: 600; cursor: pointer; text-align: center;
      transition: all 0.14s ease;
    }
    .tx-btn:hover { border-color: var(--accent); color: var(--accent); }

    .full-code {
      background: #04060c; border: 1px solid var(--border); border-radius: 11px;
      padding: 14px; font-family: "SF Mono", Menlo, monospace; font-size: 0.82rem;
      color: #e2e8f0; white-space: pre-wrap; word-break: break-word;
      min-height: 210px; max-height: 310px; overflow-y: auto; margin-bottom: 16px;
    }

    .chart-box { border-top: 1px solid var(--border); padding-top: 14px; }
    .chart-row { margin-bottom: 9px; }
    .chart-label { display: flex; justify-content: space-between; font-size: 0.78rem; color: var(--muted); margin-bottom: 4px; }
    .bar-track { height: 7px; background: var(--surface-elevated); border-radius: 999px; overflow: hidden; }
    .bar-val { height: 100%; border-radius: 999px; transition: width 0.4s ease; }

    .toast {
      position: fixed; bottom: 22px; right: 22px;
      background: #0f172a; border: 1px solid var(--accent); color: var(--text);
      padding: 11px 16px; border-radius: 11px; font-size: 0.84rem; font-weight: 600;
      box-shadow: 0 12px 30px rgba(0,0,0,0.5);
      opacity: 0; transform: translateY(10px); transition: all 0.2s ease; pointer-events: none;
    }
    .toast.show { opacity: 1; transform: translateY(0); }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="logo">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div>
          <h1>PasteGuard <span class="pro-tag">PRO FIREWALL</span></h1>
          <div class="brand-sub">Real-Time macOS Clipboard Intelligence &amp; Credential Leak Prevention &bull; Bharath Kumar R (itsmerbk)</div>
        </div>
      </div>

      <div class="top-controls">
        <div class="shield-box">
          <span>Auto-Shield Scrub</span>
          <label class="switch">
            <input type="checkbox" id="shieldToggle" checked onchange="toggleShield(this.checked)" />
            <span class="slider"></span>
          </label>
        </div>
        <button class="sim-btn" onclick="simulateLeak()">&#9889; Simulate Secret Leak</button>
        <div class="live-badge"><span class="pulse-dot"></span> LIVE STREAMING</div>
      </div>
    </header>

    <section class="kpi-grid">
      <div class="kpi">
        <div class="kpi-title">Total Captures</div>
        <div class="kpi-num" id="kpiTotal">0</div>
        <div class="kpi-foot">Real-time SSE stream (&lt;350ms)</div>
      </div>
      <div class="kpi danger">
        <div class="kpi-title">Secrets Intercepted</div>
        <div class="kpi-num" style="color:var(--red);" id="kpiSecrets">0</div>
        <div class="kpi-foot">Regex + Shannon entropy engine</div>
      </div>
      <div class="kpi">
        <div class="kpi-title">Latest Source App</div>
        <div class="kpi-num" style="font-size:1.3rem;padding-top:4px;color:var(--accent);" id="kpiApp">macOS</div>
        <div class="kpi-foot">Active macOS window attribution</div>
      </div>
      <div class="kpi safe">
        <div class="kpi-title">Clipboard Firewall</div>
        <div class="kpi-num" style="font-size:1.3rem;padding-top:4px;color:var(--green);" id="kpiShield">ARMED</div>
        <div class="kpi-foot">Auto-redacts leaked keys on copy</div>
      </div>
    </section>

    <main class="workspace">
      <div class="panel">
        <input class="search-box" id="searchBox" placeholder="Filter live clipboard stream by text, code, app name, or secret type..." oninput="render()" />
        <div class="filter-bar">
          <button class="pill active" onclick="setFilter('ALL', this)">All</button>
          <button class="pill" onclick="setFilter('SECRET', this)">Secrets</button>
          <button class="pill" onclick="setFilter('CODE', this)">Code</button>
          <button class="pill" onclick="setFilter('COMMAND', this)">Commands</button>
          <button class="pill" onclick="setFilter('URL', this)">URLs</button>
          <button class="pill" onclick="setFilter('PINNED', this)">Pinned</button>
          <button class="pill purge" onclick="purgeSecrets()">Purge Secrets</button>
        </div>
        <div class="feed-list" id="feedList"></div>
      </div>

      <div class="panel">
        <div class="inspector-head">
          <div>
            <div class="inspector-title">Snippet Inspector &amp; Transform Studio</div>
            <div style="font-size:0.78rem;color:var(--muted);" id="inspMeta">Select any clip on the left to inspect or transform</div>
          </div>
          <button class="mini-btn" onclick="copyInspected()">Copy Output</button>
        </div>

        <div class="transform-grid">
          <button class="tx-btn" onclick="runTransform('redact')">&#128737; Redact Secrets</button>
          <button class="tx-btn" onclick="runTransform('json_pretty')">{ } Prettify JSON</button>
          <button class="tx-btn" onclick="runTransform('b64_encode')">Base64 Encode</button>
          <button class="tx-btn" onclick="runTransform('b64_decode')">Base64 Decode</button>
          <button class="tx-btn" onclick="runTransform('extract_urls')">Extract URLs</button>
          <button class="tx-btn" onclick="runTransform('curl_to_py')">cURL &rarr; Python</button>
        </div>

        <pre class="full-code" id="inspCode">Press Cmd + C anywhere on your MacBook to capture live...</pre>

        <div class="chart-box">
          <div style="font-size:0.8rem;font-weight:700;margin-bottom:10px;color:var(--muted);">LIVE CAPTURE TELEMETRY</div>
          <div id="telemetryBars"></div>
        </div>
      </div>
    </main>
  </div>
  <div class="toast" id="toast"></div>

  <script>
    let clips = [];
    let filterMode = 'ALL';
    let selectedId = null;

    function toast(msg) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.classList.add('show');
      setTimeout(() => el.classList.remove('show'), 2100);
    }

    function esc(s) {
      return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function setFilter(mode, btn) {
      filterMode = mode;
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      render();
    }

    function selectClip(id) {
      selectedId = id;
      const item = clips.find(c => c.id === id);
      if (item) {
        document.getElementById('inspMeta').textContent =
          `${item.category} • Captured from ${item.source_app || 'macOS'} at ${item.updated_at}`;
        document.getElementById('inspCode').textContent =
          item.category === 'SECRET' ? item.redacted : item.content;
      }
      render();
    }

    function renderTelemetry() {
      const total = Math.max(clips.length, 1);
      const counts = {
        CODE: clips.filter(c => c.category === 'CODE' || c.category === 'COMMAND').length,
        SECRET: clips.filter(c => c.category === 'SECRET').length,
        URL: clips.filter(c => c.category === 'URL' || c.category === 'JSON').length,
        TEXT: clips.filter(c => c.category === 'TEXT').length,
      };
      const rows = [
        { label: 'Code & Terminal Commands', val: counts.CODE, color: '#818cf8' },
        { label: 'Secrets Intercepted', val: counts.SECRET, color: '#f43f5e' },
        { label: 'URLs & Structured JSON', val: counts.URL, color: '#38bdf8' },
        { label: 'Plain Text Snippets', val: counts.TEXT, color: '#10b981' },
      ];
      document.getElementById('telemetryBars').innerHTML = rows.map(r => `
        <div class="chart-row">
          <div class="chart-label"><span>${r.label}</span><span>${r.val}</span></div>
          <div class="bar-track"><div class="bar-val" style="width:${Math.round((r.val/total)*100)}%;background:${r.color};"></div></div>
        </div>
      `).join('');
    }

    function render() {
      const q = document.getElementById('searchBox').value.toLowerCase();
      document.getElementById('kpiTotal').textContent = clips.length;
      document.getElementById('kpiSecrets').textContent = clips.filter(c => c.category === 'SECRET').length;
      if (clips.length > 0) {
        document.getElementById('kpiApp').textContent = clips[0].source_app || 'macOS';
      }

      const list = clips.filter(c => {
        if (filterMode === 'PINNED' && !c.pinned) return false;
        if (filterMode !== 'ALL' && filterMode !== 'PINNED' && c.category !== filterMode) return false;
        if (q) {
          const hay = `${c.content} ${c.source_app || ''} ${c.secret_type || ''}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const container = document.getElementById('feedList');
      if (!list.length) {
        container.innerHTML = '<div class="clip-card" style="text-align:center;color:var(--muted);">No matching captures. Highlight text anywhere on your Mac and press <b>Cmd + C</b>.</div>';
        renderTelemetry();
        return;
      }

      container.innerHTML = list.map(item => {
        const isSecret = item.category === 'SECRET';
        const preview = isSecret ? item.redacted : item.content;
        return `
          <div class="clip-card ${isSecret ? 'secret' : ''} ${item.id === selectedId ? 'selected' : ''}" onclick="selectClip(${item.id})">
            <div class="card-head">
              <div class="tag-row">
                <span class="badge ${item.category}">${isSecret ? '&#9888; ' + esc(item.secret_type) : item.category}</span>
                <span class="badge app">${esc(item.source_app || 'macOS')}</span>
                <span style="font-size:0.73rem;color:var(--muted);">${item.updated_at} &bull; ${item.copy_count}x</span>
                ${item.shielded ? '<span class="shielded-tag">&#10003; Auto-Scrubbed</span>' : ''}
              </div>
              <div class="card-btns" onclick="event.stopPropagation()">
                ${isSecret ? `<button class="mini-btn red" onclick="copyClip(${item.id}, true)">Copy Safe</button>` : ''}
                <button class="mini-btn" onclick="copyClip(${item.id}, false)">Copy</button>
                <button class="mini-btn" onclick="pinClip(${item.id})">${item.pinned ? '&#9733;' : '&#9734;'}</button>
                <button class="mini-btn" onclick="delClip(${item.id})">&times;</button>
              </div>
            </div>
            <div class="snippet-preview">${esc(preview)}</div>
          </div>
        `;
      }).join('');
      renderTelemetry();
    }

    async function loadClips() {
      const res = await fetch('/api/items');
      clips = await res.json();
      if (clips.length && !selectedId) {
        selectClip(clips[0].id);
      } else {
        render();
      }
    }

    async function copyClip(id, redacted) {
      await fetch('/api/copy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, redacted })
      });
      toast(redacted ? 'Copied redacted safe key to macOS clipboard!' : 'Copied to macOS clipboard!');
    }

    async function copyInspected() {
      const text = document.getElementById('inspCode').textContent;
      await fetch('/api/set_clipboard', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      toast('Copied inspector output to macOS clipboard!');
    }

    async function runTransform(mode) {
      const text = document.getElementById('inspCode').textContent;
      const res = await fetch('/api/transform', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, mode })
      });
      const data = await res.json();
      document.getElementById('inspCode').textContent = data.result;
      toast('Transformed & copied to macOS clipboard!');
    }

    async function toggleShield(enabled) {
      await fetch('/api/shield', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      const el = document.getElementById('kpiShield');
      el.textContent = enabled ? 'ARMED' : 'MONITOR ONLY';
      el.style.color = enabled ? 'var(--green)' : 'var(--amber)';
      toast(enabled ? 'Auto-Shield Firewall ARMED' : 'Auto-Shield switched to Monitor Mode');
    }

    async function simulateLeak() {
      await fetch('/api/simulate_leak', { method: 'POST' });
    }

    async function pinClip(id) {
      await fetch('/api/pin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      loadClips();
    }

    async function delClip(id) {
      await fetch('/api/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      clips = clips.filter(c => c.id !== id);
      render();
    }

    async function purgeSecrets() {
      await fetch('/api/purge_secrets', { method: 'POST' });
      clips = clips.filter(c => c.category !== 'SECRET');
      render();
      toast('Purged all intercepted secrets from SQLite & clipboard!');
    }

    const es = new EventSource('/events');
    es.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'clip_update') {
        clips = [msg.item, ...clips.filter(c => c.id !== msg.item.id)];
        selectClip(msg.item.id);
        if (msg.item.category === 'SECRET') {
          toast(`BLOCKED: ${msg.item.secret_type} scrubbed from clipboard!`);
        }
      }
    };

    loadClips();
  </script>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            with sse_lock:
                sse_clients.append(self.wfile)
            try:
                while True:
                    time.sleep(15)
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except Exception:
                with sse_lock:
                    if self.wfile in sse_clients:
                        sse_clients.remove(self.wfile)
            return

        if parsed.path == "/api/items":
            with db_lock:
                rows = conn.execute("SELECT * FROM clips ORDER BY pinned DESC, id DESC LIMIT 150").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["redacted"] = redact_secret(d["content"]) if d["secret_type"] else None
                d["shielded"] = False
                out.append(d)
            self.send_json(out)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        global auto_shield_enabled, leak_idx
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

        if self.path == "/api/copy":
            clip_id = int(payload.get("id", 0))
            redacted = bool(payload.get("redacted", False))
            with db_lock:
                row = conn.execute("SELECT content, secret_type FROM clips WHERE id = ?", (clip_id,)).fetchone()
            if row:
                text = redact_secret(row["content"]) if (redacted and row["secret_type"]) else row["content"]
                set_macos_clipboard(text)
            self.send_json({"ok": True})
            return

        if self.path == "/api/set_clipboard":
            set_macos_clipboard(str(payload.get("text", "")))
            self.send_json({"ok": True})
            return

        if self.path == "/api/transform":
            try:
                res = transform_text(str(payload.get("text", "")), str(payload.get("mode", "")))
                set_macos_clipboard(res)
                self.send_json({"result": res})
            except Exception as exc:
                self.send_json({"result": f"Transform error: {exc}"})
            return

        if self.path == "/api/shield":
            auto_shield_enabled = bool(payload.get("enabled", True))
            self.send_json({"enabled": auto_shield_enabled})
            return

        if self.path == "/api/simulate_leak":
            sample = SAMPLE_LEAKS[leak_idx % len(SAMPLE_LEAKS)]
            leak_idx += 1
            set_macos_clipboard(sample)
            self.send_json({"ok": True})
            return

        if self.path == "/api/pin":
            clip_id = int(payload.get("id", 0))
            with db_lock:
                conn.execute("UPDATE clips SET pinned = 1 - pinned WHERE id = ?", (clip_id,))
                conn.commit()
            self.send_json({"ok": True})
            return

        if self.path == "/api/delete":
            clip_id = int(payload.get("id", 0))
            with db_lock:
                conn.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
                conn.commit()
            self.send_json({"ok": True})
            return

        if self.path == "/api/purge_secrets":
            with db_lock:
                conn.execute("DELETE FROM clips WHERE category = 'SECRET'")
                conn.commit()
            set_macos_clipboard("")
            self.send_json({"ok": True})
            return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    with db_lock:
        conn.execute("DELETE FROM clips WHERE category = 'SECRET'")
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM clips").fetchone()[0]
    if count == 0:
        save_clip("git clone https://github.com/itsmerbk/pasteguard.git", source_app="Terminal")

    threading.Thread(target=clipboard_watcher, daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(0.7), webbrowser.open(f"http://{HOST}:{PORT}")), daemon=True).start()

    print(f"PasteGuard Pro live at http://{HOST}:{PORT}")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPasteGuard Pro stopped.")
