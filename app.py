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

SECRET_PATTERNS = [
    ("GitHub Token", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("AI / API Secret Key", re.compile(r"\b(sk-[A-Za-z0-9\-_]{20,})\b")),
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("JWT / Bearer Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with db_lock:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS clips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_hash TEXT UNIQUE,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                secret_type TEXT,
                pinned INTEGER DEFAULT 0,
                copy_count INTEGER DEFAULT 1,
                updated_at TEXT NOT NULL
            )
        ''')
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
    for token in text.split():
        if len(token) >= 32 and " " not in token and not token.startswith("http"):
            if shannon_entropy(token) >= 4.3:
                return "High-Entropy Secret"
    return None

def redact_secret(text: str) -> str:
    redacted = text
    for _, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: m.group(0)[:6] + "..." + "*" * 10, redacted)
    if redacted == text:
        tokens = [
            (t[:6] + "..." + "*" * 8) if (len(t) >= 32 and shannon_entropy(t) >= 4.3) else t
            for t in text.split(" ")
        ]
        redacted = " ".join(tokens)
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
    cmd_prefixes = ("git ", "python", "npm ", "brew ", "docker ", "curl ", "cd ", "ls ", "gh ", "javac ", "java ")
    if stripped.startswith(cmd_prefixes) and len(stripped.splitlines()) <= 3:
        return "COMMAND", None
    code_markers = ("def ", "class ", "import ", "const ", "function ", "public static", "#include", "=>")
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

def save_clip(text: str):
    if not text or not text.strip():
        return None
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    category, secret_type = classify_content(text)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_lock:
        existing = conn.execute("SELECT id, copy_count FROM clips WHERE content_hash = ?", (digest,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE clips SET copy_count = ?, updated_at = ? WHERE id = ?",
                (existing["copy_count"] + 1, now, existing["id"]),
            )
            row_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO clips (content_hash, content, category, secret_type, updated_at) VALUES (?, ?, ?, ?, ?)",
                (digest, text, category, secret_type, now),
            )
            row_id = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM clips WHERE id = ?", (row_id,)).fetchone()
    item = dict(row)
    item["redacted"] = redact_secret(item["content"]) if item["secret_type"] else None
    return item

def clipboard_watcher() -> None:
    last_hash = ""
    while True:
        current = get_macos_clipboard()
        if current and current.strip():
            h = hashlib.sha256(current.encode("utf-8")).hexdigest()
            if h != last_hash:
                last_hash = h
                item = save_clip(current)
                if item:
                    broadcast_sse({"type": "clip_update", "item": item})
        time.sleep(0.4)

HTML_PAGE = r'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PasteGuard - Real-Time macOS Clipboard &amp; Secret Firewall</title>
  <style>
    :root {
      --bg: #090d16;
      --panel: #111827;
      --panel-alt: #1a2234;
      --border: #263248;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --purple: #a855f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 24px;
    }
    .wrap { max-width: 1180px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
      padding-bottom: 18px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }
    h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    .sub { color: var(--muted); font-size: 0.88rem; margin-top: 4px; }
    .live-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 185, 129, 0.14);
      border: 1px solid rgba(16, 185, 129, 0.4);
      color: var(--green);
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 600;
    }
    .dot {
      width: 8px; height: 8px; border-radius: 50%; background: var(--green);
      box-shadow: 0 0 10px var(--green);
      animation: pulse 1.4s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }

    .stats {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 18px;
    }
    .stat {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
    }
    .stat-k { font-size: 0.76rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-v { font-size: 1.55rem; font-weight: 700; margin-top: 4px; }

    .toolbar {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 18px;
    }
    .search {
      flex: 1;
      min-width: 240px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 14px;
      color: var(--text);
      font-size: 0.92rem;
      outline: none;
    }
    .search:focus { border-color: var(--accent); }
    .filter-btn {
      background: var(--panel);
      border: 1px solid var(--border);
      color: var(--muted);
      padding: 8px 14px;
      border-radius: 10px;
      font-size: 0.84rem;
      font-weight: 600;
      cursor: pointer;
    }
    .filter-btn.active {
      background: rgba(56, 189, 248, 0.16);
      border-color: var(--accent);
      color: var(--accent);
    }
    .purge-btn {
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: var(--red);
      padding: 8px 14px;
      border-radius: 10px;
      font-size: 0.84rem;
      font-weight: 600;
      cursor: pointer;
    }

    .feed { display: flex; flex-direction: column; gap: 12px; }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 15px 16px;
      transition: border-color 0.2s ease;
    }
    .card.secret { border-color: rgba(239, 68, 68, 0.65); background: linear-gradient(180deg, rgba(239,68,68,0.08), var(--panel)); }
    .card-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }
    .badges { display: flex; align-items: center; gap: 8px; font-size: 0.76rem; }
    .cat {
      padding: 3px 9px;
      border-radius: 6px;
      font-weight: 700;
      background: var(--panel-alt);
      color: var(--accent);
      border: 1px solid var(--border);
    }
    .cat.SECRET { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border-color: var(--red); }
    .cat.CODE { color: var(--purple); }
    .cat.COMMAND { color: var(--green); }
    .cat.URL { color: var(--amber); }
    .time { color: var(--muted); }

    .actions { display: flex; gap: 6px; }
    .act-btn {
      background: var(--panel-alt);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 5px 10px;
      border-radius: 7px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
    }
    .act-btn:hover { border-color: var(--accent); }
    .act-btn.warn { border-color: rgba(239, 68, 68, 0.5); color: #fca5a5; }
    .act-btn.pinned { border-color: var(--amber); color: var(--amber); }

    pre {
      background: #070a11;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 11px 12px;
      font-family: "SF Mono", Menlo, monospace;
      font-size: 0.83rem;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 170px;
      overflow-y: auto;
      color: #e2e8f0;
    }
    .toast {
      position: fixed;
      bottom: 22px;
      right: 22px;
      background: #0f172a;
      border: 1px solid var(--accent);
      color: var(--text);
      padding: 10px 16px;
      border-radius: 10px;
      font-size: 0.86rem;
      font-weight: 600;
      opacity: 0;
      transform: translateY(10px);
      transition: all 0.2s ease;
      pointer-events: none;
    }
    .toast.show { opacity: 1; transform: translateY(0); }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>PasteGuard &mdash; Real-Time Clipboard &amp; Secret Firewall</h1>
        <div class="sub">Copy anything with <b>Cmd + C</b> on your MacBook &bull; Built by Bharath Kumar R (itsmerbk)</div>
      </div>
      <div class="live-pill"><span class="dot"></span> LIVE STREAMING macOS CLIPBOARD</div>
    </header>

    <div class="stats">
      <div class="stat"><div class="stat-k">Captured Clips</div><div class="stat-v" id="stTotal">0</div></div>
      <div class="stat"><div class="stat-k">Secrets Intercepted</div><div class="stat-v" style="color:var(--red);" id="stSecrets">0</div></div>
      <div class="stat"><div class="stat-k">Code &amp; Commands</div><div class="stat-v" style="color:var(--accent);" id="stCode">0</div></div>
      <div class="stat"><div class="stat-k">Pinned Snippets</div><div class="stat-v" style="color:var(--amber);" id="stPinned">0</div></div>
    </div>

    <div class="toolbar">
      <input class="search" id="searchInput" placeholder="Search live clipboard history (code, commands, URLs, keys)..." oninput="render()" />
      <button class="filter-btn active" onclick="setFilter('ALL', this)">All</button>
      <button class="filter-btn" onclick="setFilter('SECRET', this)">Secrets</button>
      <button class="filter-btn" onclick="setFilter('CODE', this)">Code</button>
      <button class="filter-btn" onclick="setFilter('COMMAND', this)">Commands</button>
      <button class="filter-btn" onclick="setFilter('URL', this)">URLs</button>
      <button class="filter-btn" onclick="setFilter('PINNED', this)">Pinned</button>
      <button class="purge-btn" onclick="purgeSecrets()">Purge All Secrets</button>
    </div>

    <div class="feed" id="feed"></div>
  </div>
  <div class="toast" id="toast"></div>

  <script>
    let items = [];
    let activeFilter = 'ALL';

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 1800);
    }

    function setFilter(f, btn) {
      activeFilter = f;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      render();
    }

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function render() {
      const q = document.getElementById('searchInput').value.toLowerCase();
      document.getElementById('stTotal').textContent = items.length;
      document.getElementById('stSecrets').textContent = items.filter(i => i.category === 'SECRET').length;
      document.getElementById('stCode').textContent = items.filter(i => i.category === 'CODE' || i.category === 'COMMAND').length;
      document.getElementById('stPinned').textContent = items.filter(i => i.pinned).length;

      const filtered = items.filter(i => {
        if (activeFilter === 'PINNED' && !i.pinned) return false;
        if (activeFilter !== 'ALL' && activeFilter !== 'PINNED' && i.category !== activeFilter) return false;
        if (q && !i.content.toLowerCase().includes(q) && !(i.secret_type || '').toLowerCase().includes(q)) return false;
        return true;
      });

      const feed = document.getElementById('feed');
      if (!filtered.length) {
        feed.innerHTML = '<div class="card" style="color:var(--muted);text-align:center;">No matching clips yet. Press <b>Cmd + C</b> anywhere on your Mac to capture live!</div>';
        return;
      }

      feed.innerHTML = filtered.map(item => {
        const isSecret = item.category === 'SECRET';
        const displayText = isSecret ? item.redacted : item.content;
        return `
          <div class="card ${isSecret ? 'secret' : ''}">
            <div class="card-top">
              <div class="badges">
                <span class="cat ${item.category}">${isSecret ? '&#9888; ' + escapeHtml(item.secret_type) : item.category}</span>
                <span class="time">${item.updated_at} &bull; Copied ${item.copy_count}x</span>
              </div>
              <div class="actions">
                ${isSecret ? `<button class="act-btn warn" onclick="copyItem(${item.id}, true)">Copy Redacted</button>` : ''}
                <button class="act-btn" onclick="copyItem(${item.id}, false)">${isSecret ? 'Copy Raw' : 'Copy'}</button>
                <button class="act-btn ${item.pinned ? 'pinned' : ''}" onclick="togglePin(${item.id})">${item.pinned ? 'Pinned' : 'Pin'}</button>
                <button class="act-btn" onclick="deleteItem(${item.id})">Delete</button>
              </div>
            </div>
            <pre>${escapeHtml(displayText)}</pre>
          </div>
        `;
      }).join('');
    }

    async function loadInitial() {
      const res = await fetch('/api/items');
      items = await res.json();
      render();
    }

    async function copyItem(id, redacted) {
      await fetch('/api/copy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, redacted })
      });
      showToast(redacted ? 'Copied redacted safe string to macOS clipboard!' : 'Copied to macOS clipboard!');
    }

    async function togglePin(id) {
      await fetch('/api/pin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      await loadInitial();
    }

    async function deleteItem(id) {
      await fetch('/api/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      items = items.filter(i => i.id !== id);
      render();
    }

    async function purgeSecrets() {
      await fetch('/api/purge_secrets', { method: 'POST' });
      items = items.filter(i => i.category !== 'SECRET');
      render();
      showToast('All intercepted secrets purged from disk & clipboard!');
    }

    const evtSource = new EventSource('/events');
    evtSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'clip_update') {
        items = [data.item, ...items.filter(i => i.id !== data.item.id)];
        render();
        if (data.item.category === 'SECRET') {
          showToast('Secret detected: ' + data.item.secret_type);
        }
      }
    };

    loadInitial();
  </script>
</body>
</html>
'''

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
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except Exception:
                with sse_lock:
                    if self.wfile in sse_clients:
                        sse_clients.remove(self.wfile)
            return

        if parsed.path == "/api/items":
            with db_lock:
                rows = conn.execute("SELECT * FROM clips ORDER BY pinned DESC, updated_at DESC, id DESC LIMIT 150").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["redacted"] = redact_secret(d["content"]) if d["secret_type"] else None
                out.append(d)
            self.send_json(out)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
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
        count = conn.execute("SELECT COUNT(*) FROM clips").fetchone()[0]
    if count == 0:
        save_clip("git clone https://github.com/itsmerbk/pasteguard.git")

    threading.Thread(target=clipboard_watcher, daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(0.7), webbrowser.open(f"http://{HOST}:{PORT}")), daemon=True).start()

    print(f"PasteGuard live at http://{HOST}:{PORT} - Press Cmd+C anywhere on your Mac!")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPasteGuard stopped.")
