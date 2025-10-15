#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime as _dt
import os
import sys
import mimetypes
import subprocess
from collections import deque
from pathlib import Path

# ---------------------------
# Defaults
# ---------------------------

DEFAULT_TRUNCATE_N = 50

DEFAULT_EXCLUDES = {
    ".git", ".svn", ".hg", ".idea", ".vscode",
    "node_modules", "dist", "build", ".next", ".cache",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "__pycache__",
}

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
    ".env.example", ".env.template",
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

# Special filenames recognized as code
SPECIAL_CODE_FILENAMES = {
    "Dockerfile": "docker",
    "Makefile": "make",
    ".gitignore": "gitignore",
    ".gitattributes": "gitattributes",
    "Procfile": "procfile",
    "Justfile": "make",
    ".env": "",
    ".env.local": "",
    ".tool-versions": "",
    "LICENSE": "",
    "LICENCE": "",
    "COPYING": "",
}

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

def is_code_file(path: Path) -> bool:
    """Decide if file should be included fully."""
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

def make_header(root: Path, mode: str):
    """Build the top section of the markdown prompt."""
    now = _dt.datetime.now().isoformat(timespec="seconds")
    lines = []
    if mode == "ack":
        lines.append("# Contexte\n")
        lines.append("Veuillez **prendre connaissance** du projet ci-dessous et **répondre uniquement** par `OK`.\n")
    elif mode == "describe":
        lines.append("# Tâche\n")
        lines.append("Veuillez **décrire** ce projet, ses objectifs, son architecture et ses dépendances principales **à partir des éléments fournis ci-dessous**.\n")
    else:
        lines.append("# Prompt Projet\n")
        lines.append("Le contenu suivant représente un export du projet sous forme de **prompt Markdown**.\n")
    lines.append("## Métadonnées\n")
    lines.append(f"- Racine : `{root}`")
    lines.append(f"- Date : `{now}`")
    lines.append(f"- Python : `{sys.version.split()[0]}`\n")
    return "\n".join(lines)

def fence(lang: str):
    """Open markdown fence for a language."""
    return f"```{lang}\n" if lang else "```\n"

def write_markdown(root: Path, files, truncate_n: int):
    """Return the whole markdown document as a string."""
    from io import StringIO
    out = StringIO()

    # Table of contents
    out.write("# Sommaire\n\n")
    for p in files:
        rel = p.relative_to(root)
        out.write(f"- [{rel}](#{anchor_from_path(rel)})\n")
    out.write("\n---\n\n")

    # File sections
    for p in files:
        rel = p.relative_to(root)
        anchor = anchor_from_path(rel)
        out.write(f"## {rel}\n\n")
        out.write(f"<a id=\"{anchor}\"></a>\n\n")

        if is_binary(p):
            out.write("> ⚠️ Fichier binaire — ignoré dans le prompt.\n\n")
            continue

        lang = ext_lang(p)
        if is_code_file(p):
            out.write(fence(lang))
            out.write(read_all_text(p))
            out.write("\n```\n\n")
        else:
            first, last = read_first_last_lines(p, truncate_n)
            out.write("> 🔎 **Fichier texte non-code — tronqué** (premières et dernières lignes)\n\n")
            out.write(fence(lang))
            if last and (last[0] != first[0] or len(last) != len(first)):
                out.writelines(first)
                out.write("\n…\n\n")
                out.writelines(last)
            else:
                out.writelines(first)
            out.write("\n```\n\n")

    return out.getvalue()

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
            # Fallback to Tkinter (may not exist)
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
        description="Export current project as a Markdown prompt."
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

    # Hide empty files if requested
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

    # Build markdown
    header = make_header(root, args.mode)
    body = write_markdown(root, files, args.truncate_n)
    md = header + "\n---\n\n" + (
        "> **Instruction LLM** : « Analyse le contenu ci-dessous et réponds uniquement `OK`. »\n\n" if args.mode == "ack" else
        "> **Instruction LLM** : « À partir des sources fournies, produis un résumé technique clair. »\n\n" if args.mode == "describe" else
        "> **Note** : Ce document sert d’entrée (prompt) à un LLM pour comprendre le projet.\n\n"
    ) + body

    # Output: stdout or file
    if args.out == "-" or not args.out:
        # Print to stdout
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
