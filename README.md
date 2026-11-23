# PasteGuard - Real-Time macOS Clipboard Intelligence & Secret-Leak Firewall

A local-first macOS background service and live Server-Sent Events (SSE) web dashboard that captures every `Cmd + C` event in real time, detects accidental API key/token leaks using regex and Shannon entropy analysis, auto-classifies code/commands/URLs/JSON, and provides instant search and one-click redaction.

## Features
- **Zero-Refresh Live Stream:** Uses `ThreadingHTTPServer` + SSE (`/events`) to push macOS `pbpaste` updates to the UI in `<400ms`.
- **Secret-Leak Firewall:** Intercepts GitHub PATs, AI/API keys (`sk-`), AWS keys, JWTs, private keys, and high-entropy secrets with one-click **Copy Redacted** and **Purge All Secrets**.
- **Zero Dependencies:** Pure Python 3 standard library + SQLite (`pasteguard.db`).

## Quickstart
    python3 app.py
