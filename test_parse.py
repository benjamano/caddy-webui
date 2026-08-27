"""Parser regression tests. Run: python3 test_parse.py

Stdlib only, no test framework, matching the rest of the project.
"""
import importlib.util
import os
import shutil
import sys
import tempfile

# Never let these tests touch a real caddy binary or reload a real service,
# no matter what cfg dicts individual tests build.
os.environ["CADDY_WEBUI_SKIP_CADDY"] = "1"

spec = importlib.util.spec_from_file_location("app", "app.py")
app = importlib.util.module_from_spec(spec)
sys.modules["app"] = app
spec.loader.exec_module(app)

kinds = lambda text: [s["kind"] for s in app.parse_document(text)]

SIMPLE = "http://a.local {\n\treverse_proxy localhost:1\n}\n"
COMMENTED = "# a comment\nhttp://a.local {\n\treverse_proxy localhost:1\n}\n"
SPACED = "# a comment\n\nhttp://a.local {\n\treverse_proxy localhost:1\n}\n"
TWO = ("# first\nhttp://a.local {\n\treverse_proxy localhost:1\n}\n\n"
       "# second\nhttp://b.local {\n\treverse_proxy localhost:2\n}\n")
MULTI = "# a comment\nhttp://c.local {\n\tencode gzip\n\treverse_proxy localhost:3\n}\n"
ONLY_COMMENTS = "# just a comment\n# and another\n"
INDENTED = "\t# indented comment\nhttp://d.local {\n\treverse_proxy localhost:4\n}\n"

# A comment directly above a site address must not hide the block.
assert "managed" in kinds(COMMENTED), kinds(COMMENTED)
assert "managed" in kinds(INDENTED), kinds(INDENTED)
assert kinds(TWO).count("managed") == 2, kinds(TWO)

# Previously-working forms must keep working.
assert "managed" in kinds(SIMPLE), kinds(SIMPLE)
assert "managed" in kinds(SPACED), kinds(SPACED)

# A block the tool does not fully understand stays read-only, never managed.
assert "opaque" in kinds(MULTI), kinds(MULTI)
assert "managed" not in kinds(MULTI), kinds(MULTI)

# A file with no site block is left alone.
assert kinds(ONLY_COMMENTS) == ["text"], kinds(ONLY_COMMENTS)

# Comments must survive a parse/render round-trip.
for name, text in (("COMMENTED", COMMENTED), ("TWO", TWO), ("MULTI", MULTI), ("INDENTED", INDENTED)):
    out = app.render_document(app.parse_document(text))
    for line in text.splitlines():
        if line.strip().startswith("#"):
            assert line in out, f"{name}: comment lost: {line!r}"

# Untouched documents round-trip byte-for-byte.
for name, text in (("MULTI", MULTI), ("ONLY_COMMENTS", ONLY_COMMENTS)):
    out = app.render_document(app.parse_document(text))
    assert out == text, f"{name}: round-trip changed the document"

# A full document with mixed formatting (tabs, odd indent) must round-trip
# byte-for-byte when nothing in it is touched -- a save must never
# re-normalise routes the user didn't edit.
MIXED = (
    "ha.example.com {\n\treverse_proxy 10.0.0.1:8123\n}\n\n"
    "www.example.com, example.com {\n\treverse_proxy 10.0.0.2:3000\n}\n\n"
    "seq.example.com {\n        reverse_proxy 10.0.0.3\n}\n\n"
    "custom.example.com {\n\treverse_proxy 10.0.0.4:9000 {\n\t\ttransport http { tls_insecure_skip_verify }\n\t}\n}\n"
)
out = app.render_document(app.parse_document(MIXED))
assert out == MIXED, "unedited mixed-formatting document changed on round-trip"

# Editing one managed route must not touch any other segment's formatting.
doc = app.parse_document(MIXED)
managed_idx = [i for i, s in enumerate(doc) if s["kind"] == "managed"][0]
doc[managed_idx]["upstream"] = "10.0.0.1:9999"
doc[managed_idx].pop("raw", None)
out = app.render_document(doc)
assert "10.0.0.1:9999" in out, "edited upstream did not apply"
assert "\treverse_proxy 10.0.0.2:3000" in out, "untouched tab-indented route was rewritten"
assert "        reverse_proxy 10.0.0.3" in out, "untouched odd-indent route was rewritten"

# --- Disable / enable ---------------------------------------------------

DISABLE_SRC = "app.example.com {\n\treverse_proxy 127.0.0.1:3000\n}\n"
doc = app.parse_document(DISABLE_SRC)
assert doc[0]["kind"] == "managed"
doc[0]["kind"] = "disabled_managed"
doc[0].pop("raw", None)
disabled_text = app.render_document(doc)
assert app.DISABLED_MARKER in disabled_text, disabled_text
for line in disabled_text.splitlines():
    if "reverse_proxy" in line:
        assert line.lstrip().startswith("#"), f"disabled block leaked a live directive: {line!r}"

# Re-parsing a disabled block must recover it as disabled_managed with the
# same address/upstream, not as inert text. (Like any top-level block, it
# may be followed by a trailing whitespace-only text segment for the final
# newline -- that's normal, see the SIMPLE/COMMENTED cases above.)
redoc = app.parse_document(disabled_text)
assert redoc[0]["kind"] == "disabled_managed", [s["kind"] for s in redoc]
assert all(s["kind"] == "text" and not s["raw"].strip() for s in redoc[1:]), redoc
assert redoc[0]["address"] == "app.example.com", redoc[0]
assert redoc[0]["upstream"] == "127.0.0.1:3000", redoc[0]

# Disabling then re-enabling must restore a working managed route.
redoc[0]["kind"] = "managed"
redoc[0].pop("raw", None)
reenabled_text = app.render_document(redoc)
final = app.parse_document(reenabled_text)
assert final[0]["kind"] == "managed", [s["kind"] for s in final]
assert all(s["kind"] == "text" and not s["raw"].strip() for s in final[1:]), final
assert final[0]["upstream"] == "127.0.0.1:3000", final[0]

# A disabled block round-trips byte-for-byte once written (idempotent --
# saving twice without touching it must not drift).
assert app.render_document(app.parse_document(disabled_text)) == disabled_text

# A comment that merely starts with the marker text but doesn't decode to a
# clean single managed block must NOT be treated as a disabled route --
# safety-first: when in doubt, leave it as inert text rather than guess.
FAKE_MARKER = app.DISABLED_MARKER + "\n# not a real route, just talking about it\n"
fake_doc = app.parse_document(FAKE_MARKER)
assert "disabled_managed" not in [s["kind"] for s in fake_doc], fake_doc
assert app.render_document(fake_doc) == FAKE_MARKER, "non-decodable marker text was altered"

# A disabled block with a trailing stray comment line (not part of the
# original block) must also be rejected, not silently absorbed.
TRAILING_JUNK = app.DISABLED_MARKER + "\n# app.example.com {\n#     reverse_proxy 127.0.0.1:3000\n# }\n# ps: unrelated note\n"
junk_doc = app.parse_document(TRAILING_JUNK)
assert "disabled_managed" not in [s["kind"] for s in junk_doc], junk_doc
assert app.render_document(junk_doc) == TRAILING_JUNK

# --- New-route insertion position ---------------------------------------

# A new route must land right after the last existing route, not after
# trailing custom/opaque blocks that happen to be further down the file.
WITH_TRAILING_CUSTOM = (
    "a.example.com {\n\treverse_proxy 10.0.0.1\n}\n\n"
    "custom.example.com {\n\treverse_proxy 10.0.0.2 {\n\t\ttransport http { tls_insecure_skip_verify }\n\t}\n}\n"
)
doc = app.parse_document(WITH_TRAILING_CUSTOM)
kinds_before = [s["kind"] for s in doc]
assert kinds_before[:2] == ["managed", "opaque"], kinds_before
assert all(s["kind"] == "text" and not s["raw"].strip() for s in doc[2:]), doc
new_seg = {"kind": "managed", "prefix": "\n\n", "address": "b.example.com", "matcher": None, "upstream": "10.0.0.3"}
insert_at = len(doc)
for j in range(len(doc) - 1, -1, -1):
    if doc[j]["kind"] in ("managed", "disabled_managed"):
        insert_at = j + 1
        break
doc.insert(insert_at, new_seg)
assert insert_at == 1, f"expected new route to land right after the existing managed route, got index {insert_at}"
assert [s["kind"] for s in doc][:3] == ["managed", "managed", "opaque"], [s["kind"] for s in doc]

# --- Backups: same-second collision must not overwrite a prior backup ----

tmpdir = tempfile.mkdtemp(prefix="caddy-webui-test-collision-")
try:
    same_ts = "20260827-120000"
    p_first = app._unique_backup_path(tmpdir, same_ts)
    open(p_first, "w").close()
    p_second = app._unique_backup_path(tmpdir, same_ts)
    assert p_second != p_first, "second save in the same second must not reuse the first backup's path"
    open(p_second, "w").close()
    p_third = app._unique_backup_path(tmpdir, same_ts)
    assert p_third not in (p_first, p_second), "third same-second save collided with an existing backup"
    assert app.BACKUP_NAME_RE.match(os.path.basename(p_second)), os.path.basename(p_second)
    assert app.BACKUP_NAME_RE.match(os.path.basename(p_third)), os.path.basename(p_third)
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)

# --- Backups: list_backups / restore_backup ------------------------------

tmpdir = tempfile.mkdtemp(prefix="caddy-webui-test-")
try:
    backup_dir = os.path.join(tmpdir, "backups")
    os.makedirs(backup_dir)
    caddyfile_path = os.path.join(tmpdir, "Caddyfile")
    with open(caddyfile_path, "w", encoding="utf-8") as f:
        f.write("a.example.com {\n\treverse_proxy 10.0.0.1\n}\n")

    # Two valid backups plus files that must be ignored (wrong name shape,
    # a directory, and a path-traversal-shaped name).
    p1 = os.path.join(backup_dir, "Caddyfile.20260101-010101")
    p2 = os.path.join(backup_dir, "Caddyfile.20260102-020202")
    with open(p1, "w", encoding="utf-8") as f:
        f.write("old content one\n")
    with open(p2, "w", encoding="utf-8") as f:
        f.write("old content two\n")
    # Explicit, distinct mtimes -- listing order must not depend on how fast
    # the filesystem's clock ticks between two writes in the same test.
    os.utime(p1, (1000, 1000))
    os.utime(p2, (2000, 2000))
    with open(os.path.join(backup_dir, "notabackup.txt"), "w", encoding="utf-8") as f:
        f.write("ignore me\n")
    # A directory that happens to match the backup name pattern must not
    # crash listing, and restoring it must fail gracefully (not a file).
    os.makedirs(os.path.join(backup_dir, "Caddyfile.20260103-030303"))

    cfg = {
        "caddyfile_path": caddyfile_path,
        "backup_dir": backup_dir,
        "caddy_bin": "caddy-does-not-exist-anywhere",
    }

    os.utime(os.path.join(backup_dir, "Caddyfile.20260103-030303"), (500, 500))
    entries = app.list_backups(cfg)
    names = [e["name"] for e in entries]
    assert names == [
        "Caddyfile.20260102-020202", "Caddyfile.20260101-010101", "Caddyfile.20260103-030303",
    ], names

    # Reject anything that isn't an exact match for our own naming scheme --
    # this is the only thing standing between /restore and path traversal.
    ok, msg = app.restore_backup(cfg, "../../../etc/passwd")
    assert not ok, "path traversal name must be rejected"
    ok, msg = app.restore_backup(cfg, "Caddyfile.20260101-010101/../../../etc/passwd")
    assert not ok, "path traversal name must be rejected"
    ok, msg = app.restore_backup(cfg, "notabackup.txt")
    assert not ok, "non-backup filename must be rejected"
    ok, msg = app.restore_backup(cfg, "Caddyfile.20260103-030303")
    assert not ok, "restoring a directory that matches the name pattern must fail, not crash"

    # A valid restore round-trips the backed-up content back onto the live
    # file (validation is skipped here since caddy_bin doesn't exist, which
    # exercises the same "caddy not found" path save_document already has).
    ok, msg = app.restore_backup(cfg, "Caddyfile.20260101-010101")
    assert ok, msg
    with open(caddyfile_path, encoding="utf-8") as f:
        assert f.read() == "old content one\n"

    # Restoring itself must have backed up the pre-restore state too.
    names_after = [e["name"] for e in app.list_backups(cfg)]
    assert len(names_after) == 4, names_after
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)

print("All parser tests passed.")
