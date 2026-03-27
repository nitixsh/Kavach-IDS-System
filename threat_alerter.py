"""
threat_alerter.py  —  KAVACH IDS Live Threat Email Notifications
=================================================================
Sends real-time email alerts via Resend when the live monitor
detects an attack.  Designed to be imported by monitor.py.

Configuration (environment variables or edit defaults below):
  RESEND_API_KEY   – your Resend API key (already used by app.py)
  RESEND_FROM      – sender address / name
  ALERT_EMAIL      – comma-separated list of alert recipient emails
                     If blank, uses the admin user's email from the DB.
  ALERT_COOLDOWN   – min seconds between emails for the SAME attack-type
                     from the SAME IP  (default: 120)
  ALERT_BATCH_SIZE – send a digest after this many queued alerts (default: 5)
"""

import os
import sqlite3
import threading
import time
import requests
from datetime import datetime
from collections import defaultdict, deque

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  (override with environment variables)
# ──────────────────────────────────────────────────────────────────────────────
RESEND_API_KEY  = os.environ.get("RESEND_API_KEY",  "re_2ANZbc3U_NjNuaCuGEAaHSJjJtpBadSF7")
RESEND_FROM     = os.environ.get("RESEND_FROM",     "KAVACH IDS <onboarding@resend.dev>")

# Comma-separated alert recipients.  Leave blank to auto-read from DB.
ALERT_EMAIL_ENV = os.environ.get("ALERT_EMAIL", "")

# Per-IP-per-attack-type cooldown in seconds (avoids inbox flooding)
ALERT_COOLDOWN_SEC  = int(os.environ.get("ALERT_COOLDOWN",   "120"))

# After this many alerts queued without sending, force a digest
ALERT_BATCH_SIZE    = int(os.environ.get("ALERT_BATCH_SIZE", "5"))

DB_PATH = "ids_database.db"


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL STATE  (thread-safe)
# ──────────────────────────────────────────────────────────────────────────────
_lock              = threading.Lock()
_last_sent         = defaultdict(float)   # key → last email timestamp
_pending_alerts    = deque()              # queued alert dicts waiting for batch
_batch_lock        = threading.Lock()
_digest_thread     = None


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _get_alert_recipients() -> list[str]:
    """Return list of email addresses to notify."""
    if ALERT_EMAIL_ENV:
        return [e.strip() for e in ALERT_EMAIL_ENV.split(",") if e.strip()]

    # Fallback: read admin / all users from DB
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT email FROM users WHERE is_active = 1 ORDER BY id LIMIT 5"
        ).fetchall()
        conn.close()
        emails = [row["email"] for row in rows if row["email"]]
        return emails if emails else []
    except Exception as e:
        print(f"[Alerter] Could not read recipients from DB: {e}")
        return []


def _cooldown_key(src_ip: str, attack_type: str) -> str:
    return f"{src_ip}::{attack_type}"


def _is_on_cooldown(src_ip: str, attack_type: str) -> bool:
    key = _cooldown_key(src_ip, attack_type)
    with _lock:
        last = _last_sent.get(key, 0)
        return (time.time() - last) < ALERT_COOLDOWN_SEC


def _mark_sent(src_ip: str, attack_type: str):
    key = _cooldown_key(src_ip, attack_type)
    with _lock:
        _last_sent[key] = time.time()


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL TEMPLATES
# ──────────────────────────────────────────────────────────────────────────────

_SEVERITY_META = {
    "DDoS Attacks":                    ("🔴", "#ef4444", "CRITICAL"),
    "Brute Force Attacks":             ("🟠", "#f97316", "HIGH"),
    "Port Scanning / Reconnaissance":  ("🟡", "#eab308", "MEDIUM"),
    "Botnet Activities":               ("🔴", "#ef4444", "CRITICAL"),
    "Service Exploits":                ("🔴", "#ef4444", "CRITICAL"),
    "Privilege Escalation":            ("🔴", "#ef4444", "CRITICAL"),
}

def _severity(attack_type: str):
    return _SEVERITY_META.get(attack_type, ("🟠", "#f97316", "HIGH"))


def _single_alert_html(alert: dict) -> str:
    icon, color, severity = _severity(alert["attack_type"])
    details_rows = "".join(
        f'<tr><td style="padding:4px 8px;color:#64748b;font-size:12px;">{k}</td>'
        f'<td style="padding:4px 8px;color:#0f172a;font-size:12px;font-weight:600;">{v}</td></tr>'
        for k, v in alert.get("details", {}).items()
    )

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">

      <!-- Header bar -->
      <div style="background:#0f172a;padding:20px 24px;border-radius:10px 10px 0 0;">
        <h2 style="font-family:monospace;color:#0ea5e9;margin:0;font-size:18px;">
          🛡️ KAVACH IDS — Threat Alert
        </h2>
        <p style="color:#94a3b8;font-size:12px;margin:4px 0 0;">
          EPG Security Platform &nbsp;·&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </p>
      </div>

      <!-- Severity badge -->
      <div style="background:{color};padding:12px 24px;text-align:center;">
        <span style="font-family:monospace;font-size:14px;font-weight:700;color:#fff;
                     letter-spacing:2px;">{icon} {severity} SEVERITY</span>
      </div>

      <!-- Body -->
      <div style="background:#ffffff;border:1px solid #e2e8f0;padding:24px;">
        <h3 style="margin:0 0 4px;color:#0f172a;font-size:16px;">
          {alert["attack_type"]} Detected
        </h3>
        <p style="color:#64748b;font-size:13px;margin:0 0 20px;">
          A threat has been detected and logged by your IDS.
        </p>

        <!-- Info table -->
        <table style="width:100%;border-collapse:collapse;
                      border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">
          <tr style="background:#f8fafc;">
            <td style="padding:4px 8px;color:#64748b;font-size:12px;">Source IP</td>
            <td style="padding:4px 8px;color:#ef4444;font-size:12px;font-weight:700;
                       font-family:monospace;">{alert.get("src_ip","Unknown")}</td>
          </tr>
          <tr>
            <td style="padding:4px 8px;color:#64748b;font-size:12px;">Destination IP</td>
            <td style="padding:4px 8px;color:#0f172a;font-size:12px;font-weight:600;
                       font-family:monospace;">{alert.get("dst_ip","Unknown")}</td>
          </tr>
          <tr style="background:#f8fafc;">
            <td style="padding:4px 8px;color:#64748b;font-size:12px;">Attack Type</td>
            <td style="padding:4px 8px;color:{color};font-size:12px;font-weight:700;">{alert["attack_type"]}</td>
          </tr>
          <tr>
            <td style="padding:4px 8px;color:#64748b;font-size:12px;">Protocol</td>
            <td style="padding:4px 8px;color:#0f172a;font-size:12px;">{alert.get("protocol","Unknown")}</td>
          </tr>
          <tr style="background:#f8fafc;">
            <td style="padding:4px 8px;color:#64748b;font-size:12px;">Confidence</td>
            <td style="padding:4px 8px;color:#0f172a;font-size:12px;">{alert.get("confidence","N/A")}</td>
          </tr>
          {details_rows}
        </table>

        <!-- Action note -->
        <div style="margin-top:20px;padding:14px;background:#fef2f2;border-left:4px solid {color};
                    border-radius:0 6px 6px 0;">
          <p style="color:#7f1d1d;font-size:13px;margin:0;">
            ⚡ <strong>Auto-action:</strong> If this IP exceeds 3 attack events it will be
            automatically blocked at the firewall level by KAVACH IDS.
          </p>
        </div>
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:14px 24px;border-radius:0 0 10px 10px;
                  border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <p style="font-family:monospace;font-size:11px;color:#94a3b8;margin:0;">
          KAVACH IDS v2.0 &nbsp;·&nbsp; EPG Security Platform &nbsp;·&nbsp;
          This is an automated security notification.
        </p>
      </div>
    </div>
    """


def _digest_html(alerts: list[dict]) -> str:
    """Compact HTML for a batch digest of multiple alerts."""
    rows = ""
    for a in alerts:
        icon, color, severity = _severity(a["attack_type"])
        rows += f"""
        <tr>
          <td style="padding:8px;font-family:monospace;font-size:12px;color:{color};">{icon} {a["attack_type"]}</td>
          <td style="padding:8px;font-family:monospace;font-size:12px;color:#ef4444;">{a.get("src_ip","?")}</td>
          <td style="padding:8px;font-size:12px;color:#64748b;">{a.get("dst_ip","?")}</td>
          <td style="padding:8px;font-size:12px;color:#94a3b8;">{a.get("timestamp","-")}</td>
        </tr>"""

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;">
      <div style="background:#0f172a;padding:20px 24px;border-radius:10px 10px 0 0;">
        <h2 style="font-family:monospace;color:#0ea5e9;margin:0;font-size:18px;">
          🛡️ KAVACH IDS — Threat Digest ({len(alerts)} alerts)
        </h2>
        <p style="color:#94a3b8;font-size:12px;margin:4px 0 0;">
          {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </p>
      </div>
      <div style="background:#fff;border:1px solid #e2e8f0;padding:0;">
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="background:#f8fafc;">
              <th style="padding:10px 8px;text-align:left;font-size:11px;color:#64748b;font-weight:600;">ATTACK TYPE</th>
              <th style="padding:10px 8px;text-align:left;font-size:11px;color:#64748b;font-weight:600;">SRC IP</th>
              <th style="padding:10px 8px;text-align:left;font-size:11px;color:#64748b;font-weight:600;">DST IP</th>
              <th style="padding:10px 8px;text-align:left;font-size:11px;color:#64748b;font-weight:600;">TIME</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
      <div style="background:#f8fafc;padding:12px 24px;border-radius:0 0 10px 10px;
                  border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <p style="font-family:monospace;font-size:11px;color:#94a3b8;margin:0;">
          KAVACH IDS v2.0 &nbsp;·&nbsp; EPG Security Platform
        </p>
      </div>
    </div>
    """


# ──────────────────────────────────────────────────────────────────────────────
# SEND HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _send_email(subject: str, html_body: str, recipients: list[str]) -> bool:
    """Low-level Resend API call.  Returns True on success."""
    if not RESEND_API_KEY:
        print(f"[Alerter] DEV MODE — would send '{subject}' to {recipients}")
        return True

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "from":    RESEND_FROM,
                "to":      recipients,
                "subject": subject,
                "html":    html_body,
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            print(f"[Alerter] ✅ Email sent → {recipients}  ({subject})")
            return True
        else:
            print(f"[Alerter] ❌ Resend error {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[Alerter] ❌ Email exception: {e}")
        return False


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def send_threat_alert(
    attack_type: str,
    src_ip:      str,
    dst_ip:      str,
    protocol:    str = "Unknown",
    confidence:  str = "N/A",
    details:     dict | None = None,
):
    """
    Call this from monitor.py whenever an attack is detected.

    Parameters
    ----------
    attack_type : str   e.g. "DDoS Attacks", "Brute Force Attacks" …
    src_ip      : str   attacker / source IP
    dst_ip      : str   target IP
    protocol    : str   TCP / UDP / ICMP / OTHER
    confidence  : str   human-readable confidence string
    details     : dict  extra key-value pairs shown in the email body
    """
    # Skip if on cooldown for this (IP, attack_type) pair
    if _is_on_cooldown(src_ip, attack_type):
        return

    recipients = _get_alert_recipients()
    if not recipients:
        print("[Alerter] ⚠️  No alert recipients configured. "
              "Set ALERT_EMAIL env var or ensure users exist in DB.")
        return

    alert = {
        "attack_type": attack_type,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    protocol,
        "confidence":  confidence,
        "details":     details or {},
        "timestamp":   datetime.now().strftime("%H:%M:%S"),
    }

    # Queue the alert
    with _batch_lock:
        _pending_alerts.append(alert)
        queue_size = len(_pending_alerts)

    _mark_sent(src_ip, attack_type)

    if queue_size >= ALERT_BATCH_SIZE:
        # Send digest immediately
        _flush_digest(recipients)
    else:
        # Send individual alert immediately (non-blocking)
        _send_individual(alert, recipients)


def _send_individual(alert: dict, recipients: list[str]):
    """Send a single alert email in a background thread."""
    def _worker():
        icon, _, severity = _severity(alert["attack_type"])
        subject = (f"{icon} [{severity}] KAVACH IDS — {alert['attack_type']} "
                   f"from {alert['src_ip']}")
        html = _single_alert_html(alert)
        _send_email(subject, html, recipients)

    threading.Thread(target=_worker, daemon=True).start()


def _flush_digest(recipients: list[str]):
    """Drain the pending queue and send a digest email."""
    with _batch_lock:
        if not _pending_alerts:
            return
        alerts = list(_pending_alerts)
        _pending_alerts.clear()

    def _worker():
        subject = f"🛡️ KAVACH IDS — Threat Digest: {len(alerts)} alerts detected"
        html = _digest_html(alerts)
        _send_email(subject, html, recipients)

    threading.Thread(target=_worker, daemon=True).start()


def send_startup_notification():
    """
    Send a one-time email when the monitor starts.
    Call this once from start_monitor() so admins know monitoring is live.
    """
    recipients = _get_alert_recipients()
    if not recipients:
        return

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;
                border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;">
      <div style="background:#0f172a;padding:20px 24px;">
        <h2 style="font-family:monospace;color:#0ea5e9;margin:0;">🛡️ KAVACH IDS</h2>
        <p style="color:#94a3b8;font-size:12px;margin:4px 0 0;">EPG Security Platform</p>
      </div>
      <div style="padding:24px;background:#fff;">
        <div style="display:inline-block;background:#dcfce7;color:#166534;
                    padding:4px 12px;border-radius:50px;font-size:12px;
                    font-family:monospace;margin-bottom:12px;">
          ● MONITOR ONLINE
        </div>
        <h3 style="margin:0 0 8px;color:#0f172a;">Live Monitoring Started</h3>
        <p style="color:#334155;font-size:13px;">
          KAVACH IDS live packet monitoring is now active.<br>
          You will receive email alerts when threats are detected.
        </p>
        <table style="margin-top:16px;width:100%;border-collapse:collapse;font-size:12px;
                      border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">
          <tr style="background:#f8fafc;">
            <td style="padding:6px 10px;color:#64748b;">Alert Cooldown</td>
            <td style="padding:6px 10px;color:#0f172a;font-family:monospace;">
              {ALERT_COOLDOWN_SEC}s per IP/attack-type
            </td>
          </tr>
          <tr>
            <td style="padding:6px 10px;color:#64748b;">Digest threshold</td>
            <td style="padding:6px 10px;color:#0f172a;font-family:monospace;">
              {ALERT_BATCH_SIZE} alerts
            </td>
          </tr>
          <tr style="background:#f8fafc;">
            <td style="padding:6px 10px;color:#64748b;">Started at</td>
            <td style="padding:6px 10px;color:#0f172a;font-family:monospace;">
              {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </td>
          </tr>
        </table>
      </div>
      <div style="background:#f8fafc;padding:12px 24px;text-align:center;">
        <p style="font-family:monospace;font-size:11px;color:#94a3b8;margin:0;">
          KAVACH IDS v2.0 &nbsp;·&nbsp; EPG Security Platform
        </p>
      </div>
    </div>
    """
    _send_email("🛡️ KAVACH IDS — Live Monitor Started", html, recipients)


def send_auto_block_notification(ip: str, attack_type: str, attack_count: int):
    """
    Call this when an IP is auto-blocked (after 3 attacks).
    Sends an immediate high-priority alert regardless of cooldown.
    """
    recipients = _get_alert_recipients()
    if not recipients:
        return

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;
                border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;">
      <div style="background:#0f172a;padding:20px 24px;">
        <h2 style="font-family:monospace;color:#ef4444;margin:0;">🚫 KAVACH IDS — IP Auto-Blocked</h2>
        <p style="color:#94a3b8;font-size:12px;margin:4px 0 0;">
          {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </p>
      </div>
      <div style="background:#fef2f2;padding:20px 24px;">
        <p style="color:#7f1d1d;font-size:14px;font-weight:700;margin:0 0 16px;">
          An IP address has been automatically blocked by the firewall.
        </p>
        <table style="width:100%;border-collapse:collapse;font-size:13px;
                      border:1px solid #fecaca;border-radius:6px;overflow:hidden;">
          <tr style="background:#fff;">
            <td style="padding:8px 12px;color:#64748b;">Blocked IP</td>
            <td style="padding:8px 12px;color:#ef4444;font-family:monospace;font-weight:700;">{ip}</td>
          </tr>
          <tr style="background:#fef2f2;">
            <td style="padding:8px 12px;color:#64748b;">Attack Type</td>
            <td style="padding:8px 12px;color:#0f172a;font-weight:600;">{attack_type}</td>
          </tr>
          <tr style="background:#fff;">
            <td style="padding:8px 12px;color:#64748b;">Attacks Logged</td>
            <td style="padding:8px 12px;color:#0f172a;font-family:monospace;">{attack_count}</td>
          </tr>
          <tr style="background:#fef2f2;">
            <td style="padding:8px 12px;color:#64748b;">Blocked At</td>
            <td style="padding:8px 12px;color:#0f172a;font-family:monospace;">
              {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </td>
          </tr>
        </table>
        <p style="color:#7f1d1d;font-size:12px;margin-top:16px;">
          You can review and unblock this IP from the KAVACH dashboard under
          <strong>Blocked IPs</strong>.
        </p>
      </div>
      <div style="background:#f8fafc;padding:12px 24px;text-align:center;">
        <p style="font-family:monospace;font-size:11px;color:#94a3b8;margin:0;">
          KAVACH IDS v2.0 &nbsp;·&nbsp; EPG Security Platform
        </p>
      </div>
    </div>
    """
    # No cooldown check — auto-block emails are always sent
    def _worker():
        _send_email(f"🚫 KAVACH IDS — IP Blocked: {ip}", html, recipients)
    threading.Thread(target=_worker, daemon=True).start()