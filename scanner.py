import threading
import hashlib
import logging
import traceback
import copy
import json
import sqlite3
import os
import queue
from datetime import datetime
from checks import ALL_CHECKS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

SEVERITY_SCORE = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 1}

# Webhook — set via /api/settings. Leave empty to disable.
_webhook_url = ""

def set_webhook(url: str):
    global _webhook_url
    _webhook_url = url.strip()

def get_webhook() -> str:
    return _webhook_url

def _send_webhook(scan: dict):
    """POST a summary to the configured webhook URL (Slack/Teams compatible)."""
    if not _webhook_url:
        return
    try:
        import requests as _requests
        findings  = scan.get("findings", [])
        score     = scan.get("score", 0)
        critical  = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high      = sum(1 for f in findings if f["severity"] == "HIGH")
        medium    = sum(1 for f in findings if f["severity"] == "MEDIUM")

        risk = "CRITICAL" if score >= 40 else "HIGH" if score >= 20 else "MEDIUM" if score >= 10 else "LOW" if score > 0 else "CLEAN"
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "✅"}.get(risk, "")

        # Slack and Teams both accept this format
        payload = {
            "text": (
                f"{emoji} *OWASP Scanner — Scan Complete*\n"
                f"*Target:* {scan.get('url')}\n"
                f"*Risk:* {risk}  |  *Score:* {score}/100\n"
                f"*Findings:* {len(findings)} total  |  "
                f"🔴 {critical} Critical  🟠 {high} High  🟡 {medium} Medium\n"
                f"*Mode:* {scan.get('mode', 'passive').upper()}  |  "
                f"*Scan ID:* {scan.get('id')}"
            )
        }
        _requests.post(_webhook_url, json=payload, timeout=5)
        log.info("Webhook notification sent for scan %s", scan.get("id"))
    except Exception:
        log.warning("Webhook failed for scan %s:\n%s", scan.get("id"), traceback.format_exc())

# DB file sits next to scanner.py
DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def _finding_key(f):
    raw = f"{f['check']}|{f['type']}|{f['url']}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _get_conn():
    """Return a SQLite connection with WAL mode for concurrency."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    """Create tables if they don't exist yet."""
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id        TEXT PRIMARY KEY,
                url       TEXT NOT NULL,
                mode      TEXT NOT NULL DEFAULT 'passive',
                status    TEXT NOT NULL DEFAULT 'running',
                started   TEXT,
                finished  TEXT,
                progress  INTEGER DEFAULT 0,
                score     INTEGER DEFAULT 0,
                checks    TEXT DEFAULT '[]',
                findings  TEXT DEFAULT '[]',
                diff      TEXT
            );

            CREATE TABLE IF NOT EXISTS history (
                normalised TEXT NOT NULL,
                scan_id    TEXT NOT NULL,
                PRIMARY KEY (normalised, scan_id)
            );
        """)
    log.info("Database ready — %s", DB_PATH)


def _save_scan(conn, scan: dict):
    """Insert or replace a full scan record."""
    conn.execute("""
        INSERT OR REPLACE INTO scans
            (id, url, mode, status, started, finished, progress, score, checks, findings, diff)
        VALUES
            (:id, :url, :mode, :status, :started, :finished, :progress, :score, :checks, :findings, :diff)
    """, {
        "id":       scan["id"],
        "url":      scan["url"],
        "mode":     scan["mode"],
        "status":   scan["status"],
        "started":  scan.get("started"),
        "finished": scan.get("finished"),
        "progress": scan.get("progress", 0),
        "score":    scan.get("score", 0),
        "checks":   json.dumps(scan.get("checks", [])),
        "findings": json.dumps(scan.get("findings", [])),
        "diff":     json.dumps(scan.get("diff")) if scan.get("diff") else None,
    })


def _row_to_scan(row) -> dict:
    """Convert a DB row back to the scan dict the rest of the app expects."""
    if row is None:
        return {}
    d = dict(row)
    d["checks"]   = json.loads(d["checks"]   or "[]")
    d["findings"] = json.loads(d["findings"] or "[]")
    d["diff"]     = json.loads(d["diff"])      if d["diff"] else None
    return d


def _load_all_scans() -> dict:
    """Load every scan from DB into memory on startup."""
    scans = {}
    with _get_conn() as conn:
        for row in conn.execute("SELECT * FROM scans"):
            s = _row_to_scan(row)
            scans[s["id"]] = s
    return scans


def _load_history() -> dict:
    """Load the normalised-URL to scan_id history map from DB."""
    history = {}
    with _get_conn() as conn:
        for row in conn.execute("SELECT normalised, scan_id FROM history ORDER BY rowid"):
            history.setdefault(row["normalised"], []).append(row["scan_id"])
    return history


class Scanner:
    MAX_CONCURRENT = 2  # max scans running at the same time

    def __init__(self):
        _init_db()
        self.lock      = threading.Lock()
        self.scans     = _load_all_scans()
        self.history   = _load_history()
        self._semaphore    = threading.Semaphore(self.MAX_CONCURRENT)
        self._queue        = queue.Queue()
        self._cancelled    = set()  # scan_ids that have been cancelled
        # Start the queue worker thread
        threading.Thread(target=self._queue_worker, daemon=True).start()
        log.info("Loaded %d scan(s) from database", len(self.scans))
    # ── Public API ───────────────────────────────────────────────

    def start_scan(self, scan_id, url, mode="passive"):
        normalised = url.rstrip("/").lower()
        scan = {
            "id":       scan_id,
            "url":      url,
            "mode":     mode,
           "status":    "queued",
            "started":  None,
            "finished": None,
            "progress": 0,
            "checks":   [],
            "findings": [],
            "score":    0,
            "diff":     None,
        }

        with self.lock:
            self.scans[scan_id] = scan
            if normalised not in self.history:
                self.history[normalised] = []
            self.history[normalised].append(scan_id)

        # Persist immediately so the scan appears in history even while running
        with _get_conn() as conn:
            _save_scan(conn, scan)
            conn.execute(
                "INSERT OR IGNORE INTO history (normalised, scan_id) VALUES (?, ?)",
                (normalised, scan_id)
            )

        self._queue.put((scan_id, url, mode, normalised))
        log.info("Scan %s queued — %s [%s]", scan_id, url, mode)

    def get_scan(self, scan_id):
        with self.lock:
            return copy.deepcopy(self.scans.get(scan_id, {}))

    def get_all_scans(self):
        with self.lock:
            return copy.deepcopy(list(self.scans.values()))

    def triage_finding(self, scan_id, index, status):
        with self.lock:
            scan = self.scans.get(scan_id)
            if not scan:
                return False
            findings = scan.get("findings", [])
            try:
                idx = int(index)
            except (TypeError, ValueError):
                return False
            if not (0 <= idx < len(findings)):
                return False
            findings[idx]["triage"] = status
            scan_copy = copy.deepcopy(scan)

        # Persist updated findings outside the lock
        with _get_conn() as conn:
            conn.execute(
                "UPDATE scans SET findings = ? WHERE id = ?",
                (json.dumps(scan_copy["findings"]), scan_id)
            )
        return True
    
    def cancel_scan(self, scan_id):
        with self.lock:
            scan = self.scans.get(scan_id)
            if not scan or scan["status"] in ("complete", "cancelled"):
                return False
            self._cancelled.add(scan_id)
            self.scans[scan_id]["status"]   = "cancelled"
            self.scans[scan_id]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with _get_conn() as conn:
            conn.execute(
                "UPDATE scans SET status='cancelled', finished=? WHERE id=?",
                (self.scans[scan_id]["finished"], scan_id)
            )
        log.info("Scan %s cancelled", scan_id)
        return True

    # ── Internal ─────────────────────────────────────────────────
    def _queue_worker(self):
        while True:
            scan_id, url, mode, normalised = self._queue.get()
            # Skip if cancelled while waiting in queue
            if scan_id in self._cancelled:
                log.info("Scan %s skipped — was cancelled while queued", scan_id)
                continue
            self._semaphore.acquire()
            with self.lock:
                # Mark as running now that a slot is free
                if self.scans.get(scan_id, {}).get("status") == "queued":
                    self.scans[scan_id]["status"] = "running"
                    self.scans[scan_id]["started"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            thread = threading.Thread(
                target=self._run_scan_slot,
                args=(scan_id, url, mode, normalised),
                daemon=True,
            )
            thread.start()

    def _run_scan_slot(self, scan_id, url, mode, normalised):
        """Wrapper that releases the semaphore slot when the scan finishes."""
        try:
            self._run_scan(scan_id, url, mode, normalised)
        finally:
            self._semaphore.release()

    def _run_scan(self, scan_id, url, mode, normalised):
        total    = len(ALL_CHECKS)
        findings = []

        for i, (name, check_fn) in enumerate(ALL_CHECKS):
            # Check cancellation before each check
            if scan_id in self._cancelled:
                log.info("Scan %s — stopping at check %d (cancelled)", scan_id, i)
                return
            with self.lock:
                self.scans[scan_id]["checks"].append({
                    "name":   name,
                    "status": "running",
                    "count":  0,
                })

            try:
                results = check_fn(url, mode)
                status  = "done"
                count   = len(results)
                findings.extend(results)
                log.info("  [%s] %s — %d finding(s)", scan_id, name, count)
            except Exception:
                log.error("  [%s] %s — check raised an exception:\n%s",
                          scan_id, name, traceback.format_exc())
                status = "error"
                count  = 0

            with self.lock:
                self.scans[scan_id]["checks"][-1]["status"] = status
                self.scans[scan_id]["checks"][-1]["count"]  = count
                self.scans[scan_id]["findings"]             = findings
                self.scans[scan_id]["progress"]             = int((i + 1) / total * 100)

            # Persist progress after every check so restarts show partial results
            with _get_conn() as conn:
                conn.execute(
                    "UPDATE scans SET checks=?, findings=?, progress=? WHERE id=?",
                    (
                        json.dumps(self.scans[scan_id]["checks"]),
                        json.dumps(findings),
                        self.scans[scan_id]["progress"],
                        scan_id,
                    )
                )

        score = min(100, sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings))
        diff  = self._compute_diff(scan_id, normalised, findings)

        with self.lock:
            self.scans[scan_id]["status"]   = "complete"
            self.scans[scan_id]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.scans[scan_id]["score"]    = score
            self.scans[scan_id]["diff"]     = diff
            final = copy.deepcopy(self.scans[scan_id])

        # Final persist
        with _get_conn() as conn:
            _save_scan(conn, final)

        log.info("Scan %s complete — score %d/100, %d finding(s)", scan_id, score, len(findings))
        _send_webhook(final)

    def _compute_diff(self, current_scan_id, normalised, current_findings):
        """
        Compare current findings against the most recent completed scan of the same URL.
        All data read atomically under lock.
        """
        with self.lock:
            prior_ids = [
                sid for sid in self.history.get(normalised, [])
                if sid != current_scan_id
                and self.scans.get(sid, {}).get("status") == "complete"
            ]
            if not prior_ids:
                return None

            prev_scan_id  = prior_ids[-1]
            prev_findings = self.scans[prev_scan_id].get("findings", [])
            prev_started  = self.scans[prev_scan_id].get("started", "")

        prev_keys    = {_finding_key(f) for f in prev_findings}
        current_keys = {_finding_key(f) for f in current_findings}

        return {
            "vs_scan_id": prev_scan_id,
            "vs_started": prev_started,
            "new":        len(current_keys - prev_keys),
            "fixed":      len(prev_keys - current_keys),
            "persisting": len(current_keys & prev_keys),
            "new_keys":   list(current_keys - prev_keys),
            "fixed_keys": list(prev_keys - current_keys),
        }