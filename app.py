#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime as _dt
import os
import sys
import mimetypes
import subprocess
import re
import fnmatch
from collections import deque
from pathlib import Path

# ---------------------------
# Defaults and safety
# ---------------------------

DEFAULT_TRUNCATE_N = 50

DEFAULT_EXCLUDES = {
    ".git", ".svn", ".hg", ".idea", ".vscode",
    "node_modules", "dist", "build", ".next", ".cache",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "__pycache__", ".ssh",
}

# Private / sensitive filenames to skip by default (glob-style)
PRIVATE_GLOBS = [
    # env and variants
    ".env", ".env.*", "*.env", ".envrc", ".env.local", ".env.production", ".env.development",
    # keys & certs
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa", "id_ed25519",
    "*.crt", "*.cer",
    # credentials files
    ".npmrc", ".pypirc", ".netrc", "auth.json", "credentials.json",
    "secrets.*", "secret.*", "config/secrets*", ".dockerconfigjson",
    "google-credentials.json", "firebase-service-account.json",
    # cloud
    "aws_credentials", "gcp_credentials*", "azure_credentials*",
]

# File extensions considered "code" (kept fully)
CODE_EXT = {
    # General
    ".txt", ".md", ".rst",
    # Web / JS
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".css", ".scss", ".sass", ".less", ".html",
    # Python
    ".py", ".pyi",
    # Java / Kotlin
    ".java", ".kt", ".kts",
    # C / C++ / Obj-C
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".m", ".mm",
    # C#
    ".cs",
    # Go / Rust / Swift
    ".go", ".rs", ".swift",
    # Ruby / PHP
    ".rb", ".php",
    # Shell / DevOps
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat",
    "Dockerfile", "dockerfile",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".json", ".jsonc",
    # Data (light)
    ".sql", ".csv", ".tsv",
    # Misc
    ".gradle", ".properties",
}

# Map extension -> markdown fence language
LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".tsx": "tsx", ".jsx": "jsx",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp",
    ".m": "objective-c", ".mm": "objective-c",
    ".cs": "csharp", ".go": "go", ".rs": "rust", ".swift": "swift",
    ".rb": "ruby", ".php": "php",
    ".sh": "bash", ".bash": "bash", ".zsh": "bash", ".fish": "bash",
    ".ps1": "powershell", ".bat": "bat",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini",
    ".json": "json", ".jsonc": "json",
    ".css": "css", ".scss": "scss", ".less": "less",
    ".html": "html", ".md": "markdown", ".rst": "rst",
    ".sql": "sql", ".csv": "csv", ".tsv": "tsv",
}

# Special filenames recognized as code (but may still be excluded by PRIVATE_GLOBS)
SPECIAL_CODE_FILENAMES = {
    "Dockerfile": "docker",
    "Makefile": "make",
    ".gitignore": "gitignore",
    ".gitattributes": "gitattributes",
    "Procfile": "procfile",
    "Justfile": "make",
    "LICENSE": "",
    "LICENCE": "",
    "COPYING": "",
}

# Secret redaction patterns (extendable)
SECRET_PATTERNS = [
    # JWT: three base64url parts separated by dots, usually starts with eyJ ({"…"} -> eyJ…)
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    # AWS Access Key ID
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # AWS Secret Access Key (heuristic)
    re.compile(r"(?i)\baws(.{0,20})?['\"][0-9A-Za-z/+]{40}['\"]"),
    # Google API key
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    # GitHub token
    re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    # OpenAI key
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    # Slack tokens
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    # Stripe secret key
    re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    # Generic long bearer tokens (heuristic)
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b"),
]

# KEY=VALUE style names to redact values for
SENSITIVE_KEYS = [
    "PASSWORD", "PASS", "SECRET", "TOKEN", "API_KEY", "API-KEY",
    "ACCESS_TOKEN", "REFRESH_TOKEN", "PRIVATE_KEY", "JWT", "AUTH",
    "CLIENT_SECRET", "DB_PASSWORD",
]

# ---------------------------
# Helpers
# ---------------------------

def is_binary(path: Path) -> bool:
    """Return True if the file is likely binary."""
    mt, _ = mimetypes.guess_type(path.as_posix())
    if mt:
        main = mt.split("/")[0]
        if main in {"image", "audio", "video", "font"}:
            return True
        if mt in {"application/pdf", "application/zip"}:
            return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
            if b"\x00" in chunk:
                return True
    except Exception:
        return True
    return False

def looks_text(path: Path) -> bool:
    """Inverse of is_binary (best effort)."""
    return not is_binary(path)

def is_private_file(path: Path) -> bool:
    """Return True if path matches a private/sensitive filename pattern."""
    name = path.name
    # Match against filename
    for pat in PRIVATE_GLOBS:
        if fnmatch.fnmatch(name, pat):
            return True
    # Also match against relative path string
    rel = path.as_posix()
    for pat in PRIVATE_GLOBS:
        if fnmatch.fnmatch(rel, pat):
            return True
    return False

def is_code_file(path: Path) -> bool:
    """Decide if file should be included fully (subject to private skip)."""
    name = path.name
    if name in SPECIAL_CODE_FILENAMES:
        return True
    ext = path.suffix.lower()
    if name.lower() in CODE_EXT or ext in CODE_EXT:
        return True
    if ext == "" and looks_text(path):
        return True
    return False

def ext_lang(path: Path) -> str:
    """Language for markdown code fence."""
    name = path.name
    if name in SPECIAL_CODE_FILENAMES:
        return SPECIAL_CODE_FILENAMES[name]
    return LANG_BY_EXT.get(path.suffix.lower(), "")

def read_first_last_lines(path: Path, n: int):
    """Read first n and last n lines without loading entire file."""
    first = []
    last = deque(maxlen=n)
    try:
        with open(path, "rb") as f:
            for i, raw in enumerate(f):
                try:
                    line = raw.decode("utf-8", errors="replace")
                except Exception:
                    line = raw.decode(errors="replace")
                if i < n:
                    first.append(line)
                last.append(line)
        return first, list(last)
    except Exception as e:
        return [f"<<Read error: {e}>>\n"], []

def read_all_text(path: Path):
    """Read full text with utf-8 fallback."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            return path.read_text(errors="replace")
        except Exception as e:
            return f"<<Read error: {e}>>"

def should_skip_dir(name: str, excludes):
    """Skip unwanted directories."""
    return name in excludes

def gather_files(root: Path, includes, excludes, follow_symlinks=False):
    """Yield project files under root, honoring includes/excludes."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d, excludes)]
        for fn in filenames:
            p = Path(dirpath) / fn
            if includes:
                matched = any(p.match(glob) for glob in includes)
                if not matched:
                    continue
            yield p

def make_header(root: Path, mode: str, skipped_private: int, redacted_hits: int, include_private: bool, redaction_on: bool):
    """Build the top section of the markdown prompt."""
    now = _dt.datetime.now().isoformat(timespec="seconds")
    lines = []
    # Short, English instructions
    if mode == "ack":
        lines.append("# Context\n")
        lines.append("Read the project below and answer only with `OK`.\n")
    elif mode == "describe":
        lines.append("# Task\n")
        lines.append("Describe this project: goals, structure, main dependencies, how to run and test.\n")
    else:
        lines.append("# Project Prompt\n")
        lines.append("Export of the project as Markdown for an LLM.\n")

    lines.append("## Meta\n")
    lines.append(f"- Root: `{root}`")
    lines.append(f"- Date: `{now}`")
    lines.append(f"- Python: `{sys.version.split()[0]}`")
    lines.append(f"- Private files included: `{include_private}`")
    lines.append(f"- Redaction enabled: `{redaction_on}`")
    lines.append(f"- Private files skipped: `{skipped_private}`")
    lines.append(f"- Redacted secrets count: `{redacted_hits}`\n")
    return "\n".join(lines)

def fence(lang: str):
    """Open markdown fence for a language."""
    return f"```{lang}\n" if lang else "```\n"

def redact_text(text: str, enabled: bool) -> (str, int):
    """Redact secrets from text and return (redacted_text, hits)."""
    if not enabled or not text:
        return text, 0

    hits = 0
    # Redact KEY=VALUE (env style)
    # Example: PASSWORD=supersecret → PASSWORD=[REDACTED]
    def _kv_redactor(match):
        nonlocal hits
        hits += 1
        return f"{match.group(1)}=[REDACTED]"

    for key in SENSITIVE_KEYS:
        # (?i) case-insensitive; allow spaces around =
        pattern = re.compile(rf"(?im)\b({re.escape(key)})\s*=\s*.+$")
        text = pattern.sub(_kv_redactor, text)

    # Redact known token formats
    for rx in SECRET_PATTERNS:
        text, n = rx.subn("[REDACTED]", text)
        hits += n

    return text, hits

def write_markdown(root: Path, files, truncate_n: int, include_private: bool, redaction_on: bool):
    """Return the whole markdown document as a string and stats (skipped_private, redacted_hits)."""
    from io import StringIO
    out = StringIO()
    skipped_private = 0
    redacted_hits_total = 0

    # Table of contents
    out.write("# Table of contents\n\n")
    for p in files:
        if is_private_file(p) and not include_private:
            continue
        rel = p.relative_to(root)
        out.write(f"- [{rel}](#{anchor_from_path(rel)})\n")
    out.write("\n---\n\n")

    # File sections
    for p in files:
        # Skip private files (unless included)
        if is_private_file(p) and not include_private:
            skipped_private += 1
            continue

        rel = p.relative_to(root)
        anchor = anchor_from_path(rel)
        out.write(f"## {rel}\n\n")
        out.write(f"<a id=\"{anchor}\"></a>\n\n")

        if is_private_file(p) and include_private:
            out.write("> ⚠️ Private file included (content may be redacted).\n\n")

        if is_binary(p):
            out.write("> ⚠️ Binary file — skipped.\n\n")
            continue

        lang = ext_lang(p)
        if is_code_file(p) and not is_private_file(p):
            # Full include
            text = read_all_text(p)
            text, hits = redact_text(text, redaction_on)
            redacted_hits_total += hits
            out.write(fence(lang))
            out.write(text)
            out.write("\n```\n\n")
        else:
            # Truncated include
            first, last = read_first_last_lines(p, truncate_n)
            first_text, h1 = redact_text("".join(first), redaction_on)
            last_text, h2 = redact_text("".join(last), redaction_on)
            redacted_hits_total += (h1 + h2)
            out.write("> 🔎 Non-code text — truncated (first and last lines shown)\n\n")
            out.write(fence(lang))
            if last and (last[0] != first[0] or len(last) != len(first)):
                out.write(first_text)
                out.write("\n…\n\n")
                out.write(last_text)
            else:
                out.write(first_text)
            out.write("\n```\n\n")

    return out.getvalue(), skipped_private, redacted_hits_total

def anchor_from_path(rel_path: Path) -> str:
    """Anchor id from path."""
    return str(rel_path).lower().replace(os.sep, "-").replace(" ", "-")

def copy_to_clipboard(text: str) -> bool:
    """Copy text to OS clipboard (best effort)."""
    try:
        if sys.platform.startswith("darwin"):
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
        elif os.name == "nt":
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
        else:
            # Try Wayland first
            for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    p.communicate(input=text.encode("utf-8"))
                    if p.returncode == 0:
                        return True
                except FileNotFoundError:
                    continue
            # Fallback to Tkinter
            try:
                import tkinter as tk
                r = tk.Tk()
                r.withdraw()
                r.clipboard_clear()
                r.clipboard_append(text)
                r.update()
                r.destroy()
                return True
            except Exception:
                return False
    except Exception:
        return False

def parse_args():
    """CLI options."""
    ap = argparse.ArgumentParser(
        description="Export current project as a Markdown prompt (safe by default)."
    )
    ap.add_argument("--mode", choices=["export", "ack", "describe"], default="export",
                    help="export (default) | ack (LLM should answer OK) | describe (LLM should describe the project).")
    ap.add_argument("-o", "--out", default="-",
                    help="Output file path, or '-' for stdout (default).")
    ap.add_argument("--truncate-n", type=int, default=DEFAULT_TRUNCATE_N,
                    help="Head/tail lines for non-code text files.")
    ap.add_argument("--include", action="append", default=[],
                    help="Glob include pattern(s).")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Directory name(s) to exclude.")
    ap.add_argument("--follow-symlinks", action="store_true",
                    help="Follow symlinks.")
    ap.add_argument("--sort", choices=["name", "path", "none"], default="path",
                    help="Sort order for files.")
    ap.add_argument("--root", default=".",
                    help="Project root (default: .).")
    ap.add_argument("--hide-empty", action="store_true",
                    help="Skip empty files.")
    ap.add_argument("--no-clipboard", action="store_true",
                    help="Do not copy result to clipboard (copied by default).")
    # New safety toggles
    ap.add_argument("--include-private", action="store_true",
                    help="Include private files (content will be redacted).")
    ap.add_argument("--no-redact", action="store_true",
                    help="Disable secret redaction (not recommended).")
    return ap.parse_args()

def main():
    """Main entry point."""
    args = parse_args()
    root = Path(args.root).resolve()

    excludes = set(DEFAULT_EXCLUDES).union(args.exclude or [])

    # Collect files
    files = list(gather_files(root, args.include, excludes, follow_symlinks=args.follow_symlinks))

    # Avoid capturing our own output file
    if args.out != "-" and args.out:
        out_path = Path(args.out).resolve()
        files = [p for p in files if p.resolve() != out_path]

    # Hide empty files
    if args.hide_empty:
        tmp = []
        for p in files:
            try:
                if p.stat().st_size > 0:
                    tmp.append(p)
            except Exception:
                pass
        files = tmp

    # Sort
    if args.sort == "name":
        files.sort(key=lambda p: p.name.lower())
    elif args.sort == "path":
        files.sort(key=lambda p: str(p).lower())

    # Build markdown with safety
    body, skipped_private, redacted_hits = write_markdown(
        root, files, args.truncate_n,
        include_private=args.include_private,
        redaction_on=(not args.no_redact),
    )

    header = make_header(
        root, args.mode,
        skipped_private=skipped_private,
        redacted_hits=redacted_hits,
        include_private=args.include_private,
        redaction_on=(not args.no_redact),
    )

    md = header + "\n---\n\n" + (
        "Please analyze the content below and answer only `OK`.\n\n" if args.mode == "ack" else
        "From the sources below, write a clear technical summary (goals, components, flows, deps, build/run, tests, limits).\n\n" if args.mode == "describe" else
        "This document is intended as LLM input to understand the project.\n\n"
    ) + body

    # Output: stdout or file
    if args.out == "-" or not args.out:
        sys.stdout.write(md)
        sys.stdout.flush()
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(md)

    # Clipboard (default on)
    if not args.no_clipboard:
        ok = copy_to_clipboard(md)
        if ok:
            print("\n[Copied to clipboard ✅]", file=sys.stderr)
        else:
            print("\n[Clipboard copy failed. Install pbcopy/clip/xclip/xsel or enable Tkinter.]", file=sys.stderr)

if __name__ == "__main__":
    main()
