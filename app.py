#!/usr/bin/env python3
"""Minimal web UI for managing reverse_proxy routes in a Caddyfile.

Standard library only. See README.md for deployment instructions.

Usage:
    python3 app.py                     Run the server (reads config from
                                        $CADDY_WEBUI_CONFIG or
                                        /etc/caddy-webui/config.json)
    python3 app.py set-password [path] Set/replace the admin password hash
                                        in the config file (prompts twice).
"""

import hashlib
import hmac
import html
import http.server
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

CONFIG_PATH = os.environ.get("CADDY_WEBUI_CONFIG", "/etc/caddy-webui/config.json")
SKIP_CADDY = os.environ.get("CADDY_WEBUI_SKIP_CADDY") == "1"

# In-memory sessions. Cleared on restart -- acceptable for a single-admin LAN tool.
SESSIONS = set()

ADDRESS_RE = re.compile(r"^[A-Za-z0-9_.\-:*,\s\$\{\}/]+$")

# Marker line written above a "disabled" route. Reserved for this tool's own
# use -- see try_parse_disabled_block().
DISABLED_MARKER = "# caddy-webui:disabled"

# Backup filenames this tool ever writes (see save_document). Restore only
# ever accepts a name matching this, both to avoid path traversal and to
# avoid restoring an arbitrary file that just happens to live in that dir.
# The optional "-N" suffix disambiguates two saves within the same second
# (timestamp has 1-second resolution) -- see _unique_backup_path().
BACKUP_NAME_RE = re.compile(r"^Caddyfile\.\d{8}-\d{6}(-\d+)?$")


# ---------------------------------------------------------------------------
# Config / auth
# ---------------------------------------------------------------------------

def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if SKIP_CADDY:
        pass  # validation/reload are skipped regardless of config contents
    return cfg


def verify_password(cfg, password):
    if not password or "password_hash" not in cfg or "password_salt" not in cfg:
        return False
    salt = bytes.fromhex(cfg["password_salt"])
    iterations = cfg.get("password_iterations", 200000)
    computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()
    return hmac.compare_digest(computed, cfg["password_hash"])


def cmd_set_password():
    import getpass

    config_path = sys.argv[2] if len(sys.argv) > 2 else CONFIG_PATH
    pw1 = getpass.getpass("New admin password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if not pw1 or pw1 != pw2:
        print("Passwords empty or did not match.", file=sys.stderr)
        sys.exit(1)

    cfg = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    salt = secrets.token_bytes(16)
    iterations = 200000
    digest = hashlib.pbkdf2_hmac("sha256", pw1.encode("utf-8"), salt, iterations).hex()
    cfg["password_salt"] = salt.hex()
    cfg["password_hash"] = digest
    cfg["password_iterations"] = iterations
    cfg.setdefault("caddyfile_path", "/etc/caddy/Caddyfile")
    cfg.setdefault("backup_dir", "/etc/caddy/caddyfile-backups")
    cfg.setdefault("listen_host", "127.0.0.1")
    cfg.setdefault("listen_port", 8080)
    cfg.setdefault("reload_cmd", ["systemctl", "reload", "caddy"])
    cfg.setdefault("caddy_bin", "caddy")
    cfg.setdefault("cookie_secure", False)

    os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass
    print(f"Password set. Config written to {config_path}")


# ---------------------------------------------------------------------------
# Caddyfile parsing
#
# The document is split into an ordered list of segments. Every segment
# renders back to exact original text unless explicitly edited through the
# UI. A block is only ever treated as "managed" (editable) when its body is
# EXACTLY one `reverse_proxy <upstream>` or `reverse_proxy <matcher> <upstream>`
# line -- anything else (custom directives, options blocks, matchers with
# braces, comments inside the body, multiple directives) is preserved as an
# opaque, read-only block. This is deliberate: the tool must never rewrite
# config it doesn't fully understand.
#
# A "disabled_managed" segment is a managed route that has been switched off
# through the UI: it's written back as a `DISABLED_MARKER` line followed by
# the whole block re-commented, so it round-trips through plain-text editors
# and `caddy validate` alike (a commented-out block is just not seen by
# Caddy). It's only ever recognised on read if it decodes back to exactly
# one clean managed block -- anything that doesn't match byte-for-byte is
# left alone as ordinary text, never guessed at.
# ---------------------------------------------------------------------------

def _skip_comment_or_string(text, i, n):
    """If text[i] starts a comment or quoted string, return the index just
    past it. Otherwise return None."""
    c = text[i]
    if c == "#":
        j = text.find("\n", i)
        return n if j == -1 else j + 1
    if c == '"':
        j = i + 1
        while j < n and text[j] != '"':
            j += 2 if text[j] == "\\" and j + 1 < n else 1
        return j + 1
    return None


def split_prefix_address(chunk):
    """Split the raw text preceding a top-level '{' into (address, prefix).
    Returns (None, None) if it doesn't look like a clean, single address."""
    last_blank = None
    for m in re.finditer(r"\n[ \t]*\n", chunk):
        last_blank = m
    if last_blank:
        prefix, addr = chunk[: last_blank.end()], chunk[last_blank.end():]
    else:
        prefix, addr = "", chunk
    # Leading comment lines belong to the prefix, not to the address. A comment
    # sitting directly above a site address is ordinary Caddyfile style, but
    # without this the '#' check below rejects the whole chunk and the block
    # disappears from the UI entirely (it becomes an unrecognised text segment).
    lines = addr.split("\n")
    keep = 0
    while keep < len(lines) - 1 and (not lines[keep].strip() or lines[keep].lstrip().startswith("#")):
        keep += 1
    if keep:
        prefix += "\n".join(lines[:keep]) + "\n"
        addr = "\n".join(lines[keep:])
    if "#" in addr or not addr.strip():
        return None, None
    if not ADDRESS_RE.match(addr.strip()):
        return None, None
    return addr, prefix


def try_parse_managed(body):
    """Return (matcher_or_None, upstream) if body is a single simple
    reverse_proxy line, else None."""
    non_empty = [l for l in body.splitlines() if l.strip() != ""]
    if len(non_empty) != 1:
        return None
    tokens = non_empty[0].strip().split()
    if not tokens or tokens[0] != "reverse_proxy":
        return None
    if len(tokens) == 2:
        return None, tokens[1]
    if len(tokens) == 3 and (tokens[1].startswith("/") or tokens[1].startswith("@")):
        return tokens[1], tokens[2]
    return None


def try_parse_disabled_block(text, marker_start, n):
    """text[marker_start:] begins with DISABLED_MARKER (caller already
    checked). If the contiguous run of comment lines that follows decodes
    to exactly one clean managed block, return (segment, end_index).
    Otherwise return (None, None) and the caller treats the marker line as
    an ordinary comment, preserving it byte-for-byte like any other text."""
    line_end = text.find("\n", marker_start)
    body_start = n if line_end == -1 else line_end + 1
    k = body_start
    while k < n:
        nl = text.find("\n", k)
        line_end_incl = n if nl == -1 else nl + 1
        if text[k:line_end_incl].lstrip().startswith("#"):
            k = line_end_incl
            continue
        break
    span = text[body_start:k]
    if not span.strip():
        return None, None

    decoded_lines = []
    for line in span.splitlines():
        rest = line.lstrip()[1:]  # drop the leading '#'
        if rest.startswith(" "):
            rest = rest[1:]
        decoded_lines.append(rest)
    decoded = "\n".join(decoded_lines) + "\n"

    sub_doc = parse_document(decoded)
    if not sub_doc or sub_doc[0]["kind"] != "managed":
        return None, None
    # Anything after the managed block itself must be pure trailing
    # whitespace (the "\n" every block naturally ends with) -- any other
    # leftover content means this wasn't a clean single block and must not
    # be guessed at.
    if any(s["kind"] != "text" or s["raw"].strip() for s in sub_doc[1:]):
        return None, None
    if render_document(sub_doc) != decoded:
        return None, None

    seg = dict(sub_doc[0])
    seg["kind"] = "disabled_managed"
    seg.pop("raw", None)
    return seg, k


def parse_document(text):
    segments = []
    n = len(text)
    i = 0
    text_start = 0
    while i < n:
        if text[i] == "#":
            line_end = text.find("\n", i)
            line = text[i: n if line_end == -1 else line_end]
            if line.rstrip("\r") == DISABLED_MARKER:
                seg, consumed_end = try_parse_disabled_block(text, i, n)
                if seg is not None:
                    seg["prefix"] = text[text_start:i]
                    segments.append(seg)
                    text_start = consumed_end
                    i = consumed_end
                    continue
        skip_to = _skip_comment_or_string(text, i, n)
        if skip_to is not None:
            i = skip_to
            continue
        if text[i] == "{":
            depth = 1
            j = i + 1
            while j < n and depth > 0:
                skip_to = _skip_comment_or_string(text, j, n)
                if skip_to is not None:
                    j = skip_to
                    continue
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            if depth != 0:
                # Unterminated block: bail out, preserve the rest verbatim.
                segments.append({"kind": "text", "raw": text[text_start:n]})
                text_start = n
                i = n
                break
            close_pos = j - 1
            chunk = text[text_start:i]
            body = text[i + 1:close_pos]
            addr, prefix = split_prefix_address(chunk)
            if addr is not None:
                raw = chunk[len(prefix):] + "{" + body + "}"
                managed = try_parse_managed(body)
                if managed is not None:
                    matcher, upstream = managed
                    segments.append({
                        "kind": "managed", "prefix": prefix, "raw": raw,
                        "address": addr.strip(), "matcher": matcher, "upstream": upstream,
                    })
                else:
                    segments.append({"kind": "opaque", "prefix": prefix, "raw": raw})
            else:
                segments.append({"kind": "text", "raw": chunk + "{" + body + "}"})
            text_start = close_pos + 1
            i = text_start
            continue
        i += 1
    if text_start < n:
        segments.append({"kind": "text", "raw": text[text_start:n]})
    return segments


def render_segment(s):
    if s["kind"] == "text":
        return s["raw"]
    if s["kind"] == "opaque":
        return s["prefix"] + s["raw"]
    if s["kind"] == "disabled_managed":
        inner = (f"reverse_proxy {s['matcher']} {s['upstream']}" if s["matcher"]
                 else f"reverse_proxy {s['upstream']}")
        lines = [f"{s['address']} {{", f"    {inner}", "}"]
        commented = "\n".join("# " + l for l in lines)
        return f"{s['prefix']}{DISABLED_MARKER}\n{commented}\n"
    # managed: replay the original bytes untouched unless this segment was
    # actually created or edited this request (no "raw" in that case) --
    # otherwise every save would re-normalise every other route's spacing.
    if "raw" in s:
        return s["prefix"] + s["raw"]
    inner = (f"reverse_proxy {s['matcher']} {s['upstream']}" if s["matcher"]
             else f"reverse_proxy {s['upstream']}")
    return f"{s['prefix']}{s['address']} {{\n    {inner}\n}}\n"


def render_document(doc):
    return "".join(render_segment(s) for s in doc)


def opaque_address_preview(raw):
    m = re.match(r"^([^{]*)\{", raw)
    return m.group(1).strip() if m else "(unparsed block)"


# ---------------------------------------------------------------------------
# Caddyfile read / validate / save
# ---------------------------------------------------------------------------

def read_caddyfile(cfg):
    path = cfg["caddyfile_path"]
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def validate_caddyfile(tmp_path, cfg):
    if SKIP_CADDY:
        return True, "validation skipped (test mode)"
    caddy_bin = cfg.get("caddy_bin", "caddy")
    if shutil.which(caddy_bin) is None:
        return True, "caddy binary not found; validation skipped"
    try:
        result = subprocess.run(
            [caddy_bin, "validate", "--config", tmp_path, "--adapter", "caddyfile"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        return False, str(e)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout).strip()
    return True, ""


def reload_caddy(cfg):
    if SKIP_CADDY:
        return True, "reload skipped (test mode)"
    cmd = cfg.get("reload_cmd", ["systemctl", "reload", "caddy"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        return False, str(e)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout).strip()
    return True, ""


def _unique_backup_path(backup_dir, ts):
    """Path for a new backup at timestamp ts, disambiguated with a -N suffix
    if a save already happened in this same second (the timestamp only has
    1-second resolution) -- two saves close together must never silently
    overwrite one another's backup."""
    base = os.path.join(backup_dir, f"Caddyfile.{ts}")
    if not os.path.exists(base):
        return base
    n = 1
    while True:
        candidate = os.path.join(backup_dir, f"Caddyfile.{ts}-{n}")
        if not os.path.exists(candidate):
            return candidate
        n += 1


def save_document(cfg, new_text):
    caddyfile_path = cfg["caddyfile_path"]
    target_dir = os.path.dirname(caddyfile_path) or "."
    os.makedirs(target_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=target_dir, prefix=".caddyfile-webui-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(new_text)

        ok, msg = validate_caddyfile(tmp_path, cfg)
        if not ok:
            return False, f"Validation failed, nothing was changed:\n{msg}"

        backup_dir = cfg.get("backup_dir") or os.path.join(target_dir, "caddyfile-backups")
        os.makedirs(backup_dir, exist_ok=True)
        if os.path.exists(caddyfile_path):
            ts = time.strftime("%Y%m%d-%H%M%S")
            shutil.copy2(caddyfile_path, _unique_backup_path(backup_dir, ts))

        os.replace(tmp_path, caddyfile_path)
        tmp_path = None  # already moved

        ok2, msg2 = reload_caddy(cfg)
        if not ok2:
            return False, f"Saved, but reload failed:\n{msg2}\nCheck the caddy service; you may need to reload it manually."
        note = f" ({msg})" if msg else ""
        return True, f"Saved and reloaded Caddy.{note}"
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def list_backups(cfg):
    backup_dir = cfg.get("backup_dir")
    if not backup_dir or not os.path.isdir(backup_dir):
        return []
    entries = []
    for name in os.listdir(backup_dir):
        if not BACKUP_NAME_RE.match(name):
            continue
        full = os.path.join(backup_dir, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        entries.append({"name": name, "mtime": st.st_mtime, "size": st.st_size})
    entries.sort(key=lambda e: (e["mtime"], e["name"]), reverse=True)
    return entries


def restore_backup(cfg, name):
    """Restore a previous backup. Goes through save_document, so the restore
    itself is validated first and the file it replaces is backed up too --
    a bad restore is exactly as recoverable as a bad save."""
    if not BACKUP_NAME_RE.match(name or ""):
        return False, "Invalid backup name."
    backup_dir = cfg.get("backup_dir") or ""
    src = os.path.join(backup_dir, name)
    if not backup_dir or not os.path.isfile(src):
        return False, "Backup not found."
    with open(src, "r", encoding="utf-8") as f:
        content = f.read()
    ok, msg = save_document(cfg, content)
    if ok:
        return True, f"Restored {name}."
    return False, msg


def validate_form(address, upstream):
    if not address or not ADDRESS_RE.match(address):
        return "Address is required and may only contain host/port characters."
    if not upstream:
        return "Upstream is required."
    return None


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

PAGE = """<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="color-scheme" content="light dark">
<title>Caddy Web UI</title>
<style>
:root {{
  --bg: #f4f5f7; --surface: #ffffff; --text: #16181d; --text-muted: #6b7280;
  --border: #e5e7eb; --primary: #2563eb; --primary-hover: #1d4ed8;
  --primary-text: #ffffff; --danger: #dc2626; --danger-hover: #b91c1c;
  --success-bg: #ecfdf5; --success-border: #a7dfc0; --success-text: #065f46;
  --error-bg: #fef2f2; --error-border: #f3c2c2; --error-text: #991b1b;
  --warn-bg: #fffbeb; --warn-border: #f5deA0; --warn-text: #92400e;
  --badge-managed-bg: #eff6ff; --badge-managed-text: #1e40af;
  --badge-custom-bg: #fffbeb; --badge-custom-text: #92400e;
  --badge-disabled-bg: #f3f4f6; --badge-disabled-text: #4b5563;
  --radius: 12px; --shadow: 0 1px 3px rgba(16,24,40,0.06);
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg: #0e1014; --surface: #1a1d23; --text: #e8e9ec; --text-muted: #9aa1ac;
    --border: #2b2f38; --primary: #3b82f6; --primary-hover: #60a5fa;
    --primary-text: #0b0d10; --danger: #f87171; --danger-hover: #fca5a5;
    --success-bg: #0d2a1e; --success-border: #14532d; --success-text: #86efac;
    --error-bg: #2c1212; --error-border: #7f1d1d; --error-text: #fca5a5;
    --warn-bg: #2a2110; --warn-border: #78350f; --warn-text: #fcd34d;
    --badge-managed-bg: #17253f; --badge-managed-text: #93c5fd;
    --badge-custom-bg: #332912; --badge-custom-text: #fcd34d;
    --badge-disabled-bg: #23262c; --badge-disabled-text: #9aa1ac;
    --shadow: 0 1px 3px rgba(0,0,0,0.4);
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  background: var(--bg); color: var(--text); margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  padding: 1.25rem 1rem 3rem; line-height: 1.45;
}}
.container {{ max-width: 620px; margin: 0 auto; }}
.topbar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; gap: 0.75rem; }}
.topbar-links {{ display: flex; gap: 0.9rem; align-items: center; }}
h1 {{ font-size: 1.25rem; margin: 0; font-weight: 700; }}
h1 .accent {{ color: var(--primary); }}
a {{ color: var(--primary); }}
.link-muted {{ color: var(--text-muted); text-decoration: none; font-size: 0.9rem; }}
.link-muted:hover {{ color: var(--text); }}
.banner {{ padding: 0.7rem 0.9rem; border-radius: var(--radius); margin-bottom: 1rem; white-space: pre-wrap; font-size: 0.92rem; border: 1px solid; }}
.banner.msg {{ background: var(--success-bg); border-color: var(--success-border); color: var(--success-text); }}
.banner.err {{ background: var(--error-bg); border-color: var(--error-border); color: var(--error-text); }}
.banner.warn {{ background: var(--warn-bg); border-color: var(--warn-border); color: var(--warn-text); }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); padding: 1rem 1.1rem; margin-bottom: 0.7rem; }}
.card.disabled-card {{ opacity: 0.72; }}
.card-top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 0.6rem; }}
.address {{ font-weight: 600; font-size: 1.02rem; word-break: break-word; }}
.badge {{ flex: none; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; padding: 0.2rem 0.5rem; border-radius: 999px; background: var(--badge-managed-bg); color: var(--badge-managed-text); white-space: nowrap; }}
.badge.custom {{ background: var(--badge-custom-bg); color: var(--badge-custom-text); }}
.badge.disabled {{ background: var(--badge-disabled-bg); color: var(--badge-disabled-text); }}
.detail {{ color: var(--text-muted); font-size: 0.88rem; margin-top: 0.3rem; word-break: break-word; }}
.detail code {{ background: var(--bg); border-radius: 5px; padding: 0.1rem 0.35rem; font-size: 0.85rem; color: var(--text); }}
.card-actions {{ margin-top: 0.8rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }}
.empty {{ text-align: center; color: var(--text-muted); padding: 2rem 1rem; }}
.btn {{
  display: inline-flex; align-items: center; justify-content: center; gap: 0.35rem;
  min-height: 42px; padding: 0.55rem 1rem; border-radius: 9px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); font-size: 0.9rem; font-weight: 600;
  cursor: pointer; text-decoration: none; -webkit-tap-highlight-color: transparent;
}}
.btn:active {{ transform: scale(0.98); }}
.btn-primary {{ background: var(--primary); border-color: var(--primary); color: var(--primary-text); }}
.btn-primary:hover {{ background: var(--primary-hover); border-color: var(--primary-hover); }}
.btn-danger {{ background: transparent; border-color: var(--danger); color: var(--danger); }}
.btn-danger:hover {{ background: var(--danger); color: #fff; }}
.btn-block {{ width: 100%; }}
form.inline {{ display: inline; }}
.add-link {{ display: block; margin-top: 1.1rem; }}
label {{ display: block; font-weight: 600; font-size: 0.9rem; margin: 1rem 0 0.35rem; }}
label:first-of-type {{ margin-top: 0; }}
.hint {{ color: var(--text-muted); font-weight: 400; font-size: 0.82rem; }}
input[type=text], input[type=password] {{
  width: 100%; padding: 0.65rem 0.75rem; border-radius: 9px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); font-size: 16px;
}}
input:focus {{ outline: 2px solid var(--primary); outline-offset: 1px; }}
.form-actions {{ display: flex; gap: 0.6rem; margin-top: 1.3rem; flex-wrap: wrap; }}
</style></head>
<body><div class="container">{body}</div></body></html>
"""


def render_login(err):
    err_html = f'<div class="banner err">{html.escape(err)}</div>' if err else ""
    body = f"""
<div class="topbar"><h1>Caddy <span class="accent">Web UI</span></h1></div>
{err_html}
<div class="card">
<form method="post" action="/login">
  <label>Password</label>
  <input type="password" name="password" autofocus autocapitalize="off" autocorrect="off">
  <div class="form-actions"><button type="submit" class="btn btn-primary btn-block">Log in</button></div>
</form>
</div>
"""
    return PAGE.format(body=body)


def render_index(qs, doc):
    msg = qs.get("msg", [""])[0]
    err = qs.get("err", [""])[0]
    flash = ""
    if msg:
        flash += f'<div class="banner msg">{html.escape(msg)}</div>'
    if err:
        flash += f'<div class="banner err">{html.escape(err)}</div>'
    warn = '<div class="banner warn">TEST MODE: caddy validate/reload are skipped.</div>' if SKIP_CADDY else ""

    cards = []
    for idx, s in enumerate(doc):
        if s["kind"] == "managed":
            detail = f'<code>{html.escape(s["upstream"])}</code>'
            if s["matcher"]:
                detail = f'{html.escape(s["matcher"])} &rarr; ' + detail
            cards.append(f"""<div class="card">
  <div class="card-top">
    <div class="address">{html.escape(s['address'])}</div>
    <span class="badge">managed</span>
  </div>
  <div class="detail">{detail}</div>
  <div class="card-actions">
    <a class="btn" href="/edit?id={idx}">Edit</a>
    <form class="inline" method="post" action="/disable?id={idx}">
      <button type="submit" class="btn">Disable</button>
    </form>
    <form class="inline" method="post" action="/delete?id={idx}" onsubmit="return confirm('Delete this route?');">
      <button type="submit" class="btn btn-danger">Delete</button>
    </form>
  </div>
</div>""")
        elif s["kind"] == "disabled_managed":
            detail = f'<code>{html.escape(s["upstream"])}</code>'
            if s["matcher"]:
                detail = f'{html.escape(s["matcher"])} &rarr; ' + detail
            cards.append(f"""<div class="card disabled-card">
  <div class="card-top">
    <div class="address">{html.escape(s['address'])}</div>
    <span class="badge disabled">disabled</span>
  </div>
  <div class="detail">{detail}</div>
  <div class="card-actions">
    <a class="btn" href="/edit?id={idx}">Edit</a>
    <form class="inline" method="post" action="/enable?id={idx}">
      <button type="submit" class="btn btn-primary">Enable</button>
    </form>
    <form class="inline" method="post" action="/delete?id={idx}" onsubmit="return confirm('Delete this route?');">
      <button type="submit" class="btn btn-danger">Delete</button>
    </form>
  </div>
</div>""")
        elif s["kind"] == "opaque":
            addr = opaque_address_preview(s["raw"])
            cards.append(f"""<div class="card">
  <div class="card-top">
    <div class="address">{html.escape(addr)}</div>
    <span class="badge custom">custom</span>
  </div>
  <div class="detail">Custom block &mdash; not editable here, preserved as-is on save.</div>
</div>""")

    list_html = "".join(cards) if cards else '<div class="card empty">No routes found.</div>'

    body = f"""
<div class="topbar"><h1>Caddy <span class="accent">Web UI</span></h1>
<div class="topbar-links"><a class="link-muted" href="/backups">Backups</a><a class="link-muted" href="/logout">Log out</a></div>
</div>
{warn}
{flash}
{list_html}
<a class="btn btn-primary btn-block add-link" href="/new">+ Add route</a>
"""
    return PAGE.format(body=body)


def render_form(idx, seg, err):
    is_edit = idx is not None
    title = "Edit route" if is_edit else "Add route"
    action = f"/edit?id={idx}" if is_edit else "/new"
    address = html.escape(seg["address"]) if seg else ""
    matcher = html.escape(seg["matcher"] or "") if seg else ""
    upstream = html.escape(seg["upstream"]) if seg else ""
    disabled_note = ""
    if seg is not None and seg.get("kind") == "disabled_managed":
        disabled_note = '<div class="banner warn">This route is disabled. Saving keeps it disabled -- use Enable on the main page to turn it back on.</div>'
    err_html = f'<div class="banner err">{html.escape(err)}</div>' if err else ""
    body = f"""
<div class="topbar"><h1>{title}</h1></div>
{err_html}
{disabled_note}
<div class="card">
<form method="post" action="{action}">
  <label>Address <span class="hint">e.g. app.example.com</span></label>
  <input type="text" name="address" value="{address}" autocapitalize="off" autocorrect="off" required>
  <label>Path matcher <span class="hint">optional, e.g. /api/*</span></label>
  <input type="text" name="matcher" value="{matcher}" autocapitalize="off" autocorrect="off">
  <label>Upstream <span class="hint">e.g. 127.0.0.1:3000</span></label>
  <input type="text" name="upstream" value="{upstream}" autocapitalize="off" autocorrect="off" required>
  <div class="form-actions">
    <button type="submit" class="btn btn-primary">Save</button>
    <a class="btn" href="/">Cancel</a>
  </div>
</form>
</div>
"""
    return PAGE.format(body=body)


def render_backups(cfg, qs):
    msg = qs.get("msg", [""])[0]
    err = qs.get("err", [""])[0]
    flash = ""
    if msg:
        flash += f'<div class="banner msg">{html.escape(msg)}</div>'
    if err:
        flash += f'<div class="banner err">{html.escape(err)}</div>'

    entries = list_backups(cfg)
    cards = []
    for e in entries:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["mtime"]))
        size = f"{e['size'] / 1024:.1f} KB" if e["size"] >= 1024 else f"{e['size']} B"
        cards.append(f"""<div class="card">
  <div class="card-top">
    <div class="address">{html.escape(when)}</div>
  </div>
  <div class="detail">{html.escape(e['name'])} &middot; {size}</div>
  <div class="card-actions">
    <form class="inline" method="post" action="/restore" onsubmit="return confirm('Restore this backup? Your current Caddyfile will be backed up first.');">
      <input type="hidden" name="name" value="{html.escape(e['name'])}">
      <button type="submit" class="btn btn-danger">Restore</button>
    </form>
  </div>
</div>""")
    list_html = "".join(cards) if cards else '<div class="card empty">No backups yet -- one is made automatically before every save.</div>'

    body = f"""
<div class="topbar"><h1>Backups</h1><a class="link-muted" href="/">&larr; Back</a></div>
{flash}
{list_html}
"""
    return PAGE.format(body=body)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

def get_cookie(handler, name):
    header = handler.headers.get("Cookie", "")
    for part in header.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "CaddyWebUI/1.0"

    def _send_html(self, body, status=200, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location, extra_headers=None):
        self.send_response(303)
        self.send_header("Location", location)
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        parsed = urllib.parse.parse_qs(raw)
        return {k: v[0] for k, v in parsed.items()}

    def _authed(self):
        token = get_cookie(self, "session")
        return token is not None and token in SESSIONS

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)

        if path == "/login":
            if self._authed():
                return self._redirect("/")
            return self._send_html(render_login(qs.get("err", [""])[0]))

        if path == "/logout":
            SESSIONS.discard(get_cookie(self, "session"))
            return self._redirect("/login", [("Set-Cookie", "session=; Path=/; Max-Age=0")])

        if not self._authed():
            return self._redirect("/login")

        cfg = load_config()

        if path == "/":
            doc = parse_document(read_caddyfile(cfg))
            return self._send_html(render_index(qs, doc))

        if path == "/new":
            return self._send_html(render_form(None, None, qs.get("err", [""])[0]))

        if path == "/edit":
            doc = parse_document(read_caddyfile(cfg))
            idx = int(qs.get("id", ["-1"])[0])
            if idx < 0 or idx >= len(doc) or doc[idx]["kind"] not in ("managed", "disabled_managed"):
                return self._redirect("/?err=" + urllib.parse.quote("Invalid route"))
            return self._send_html(render_form(idx, doc[idx], qs.get("err", [""])[0]))

        if path == "/backups":
            return self._send_html(render_backups(cfg, qs))

        return self._send_html("Not found", 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)

        if path == "/login":
            form = self._read_form()
            cfg = load_config()
            if verify_password(cfg, form.get("password", "")):
                token = secrets.token_hex(32)
                SESSIONS.add(token)
                secure = "; Secure" if cfg.get("cookie_secure") else ""
                cookie = f"session={token}; Path=/; HttpOnly; SameSite=Strict{secure}"
                return self._redirect("/", [("Set-Cookie", cookie)])
            return self._redirect("/login?err=" + urllib.parse.quote("Invalid password"))

        if not self._authed():
            return self._redirect("/login")

        cfg = load_config()

        if path == "/restore":
            form = self._read_form()
            ok, msg = restore_backup(cfg, form.get("name", ""))
            if ok:
                return self._redirect("/backups?msg=" + urllib.parse.quote(msg))
            return self._redirect("/backups?err=" + urllib.parse.quote(msg))

        form = self._read_form()
        doc = parse_document(read_caddyfile(cfg))

        if path == "/new":
            address = form.get("address", "").strip()
            matcher = form.get("matcher", "").strip() or None
            upstream = form.get("upstream", "").strip()
            err = validate_form(address, upstream)
            if err:
                return self._redirect("/new?err=" + urllib.parse.quote(err))
            new_seg = {"kind": "managed", "prefix": "\n\n", "address": address,
                       "matcher": matcher, "upstream": upstream}
            # Insert right after the last existing route, rather than always
            # at the very end of the file (which can land after unrelated
            # trailing custom blocks). Falls back to appending if this is
            # the first route in the file.
            insert_at = len(doc)
            for j in range(len(doc) - 1, -1, -1):
                if doc[j]["kind"] in ("managed", "disabled_managed"):
                    insert_at = j + 1
                    break
            doc.insert(insert_at, new_seg)
            return self._apply(cfg, doc)

        if path == "/edit":
            idx = int(qs.get("id", ["-1"])[0])
            if idx < 0 or idx >= len(doc) or doc[idx]["kind"] not in ("managed", "disabled_managed"):
                return self._redirect("/?err=" + urllib.parse.quote("Invalid route"))
            address = form.get("address", "").strip()
            matcher = form.get("matcher", "").strip() or None
            upstream = form.get("upstream", "").strip()
            err = validate_form(address, upstream)
            if err:
                return self._redirect(f"/edit?id={idx}&err=" + urllib.parse.quote(err))
            doc[idx]["address"] = address
            doc[idx]["matcher"] = matcher
            doc[idx]["upstream"] = upstream
            doc[idx].pop("raw", None)
            return self._apply(cfg, doc)

        if path == "/disable":
            idx = int(qs.get("id", ["-1"])[0])
            if idx < 0 or idx >= len(doc) or doc[idx]["kind"] != "managed":
                return self._redirect("/?err=" + urllib.parse.quote("Invalid route"))
            doc[idx]["kind"] = "disabled_managed"
            doc[idx].pop("raw", None)
            return self._apply(cfg, doc)

        if path == "/enable":
            idx = int(qs.get("id", ["-1"])[0])
            if idx < 0 or idx >= len(doc) or doc[idx]["kind"] != "disabled_managed":
                return self._redirect("/?err=" + urllib.parse.quote("Invalid route"))
            doc[idx]["kind"] = "managed"
            doc[idx].pop("raw", None)
            return self._apply(cfg, doc)

        if path == "/delete":
            idx = int(qs.get("id", ["-1"])[0])
            if idx < 0 or idx >= len(doc) or doc[idx]["kind"] not in ("managed", "disabled_managed"):
                return self._redirect("/?err=" + urllib.parse.quote("Invalid route"))
            prefix = doc[idx].get("prefix", "")
            if prefix:
                doc[idx] = {"kind": "text", "raw": prefix}
            else:
                del doc[idx]
            return self._apply(cfg, doc)

        return self._send_html("Not found", 404)

    def _apply(self, cfg, doc):
        ok, msg = save_document(cfg, render_document(doc))
        if ok:
            return self._redirect("/?msg=" + urllib.parse.quote(msg))
        return self._redirect("/?err=" + urllib.parse.quote(msg))


def main():
    cfg = load_config()
    host = cfg.get("listen_host", "127.0.0.1")
    port = cfg.get("listen_port", 8080)
    server = http.server.ThreadingHTTPServer((host, port), Handler)
    print(f"caddy-webui listening on http://{host}:{port}" + (" (TEST MODE)" if SKIP_CADDY else ""))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "set-password":
        cmd_set_password()
    else:
        main()
