"""Parser regression tests. Run: python3 test_parse.py

Stdlib only, no test framework, matching the rest of the project.
"""
import importlib.util
import sys

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

print("All parser tests passed.")
