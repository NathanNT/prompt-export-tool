# Export Project Prompt

A small Python script that exports your project as a **Markdown prompt** for AI tools like ChatGPT.
It collects all files, keeps code files fully, and shortens others.
By default, it also **copies the result to your clipboard**.

---

## How to Use

Run this script from your project folder:

```bash
python3 export_project_prompt.py
```

It will:

* Scan all files in the folder
* Keep code files complete
* Show only the first and last 50 lines of large text files
* Skip binary files
* Copy the Markdown output to your clipboard

You can also save it to a file:

```bash
python3 export_project_prompt.py -o project_prompt.md
```

---

## Modes

| Mode       | Description                        |
| ---------- | ---------------------------------- |
| `export`   | Default — full project export      |
| `ack`      | Ask the AI to just say “OK”        |
| `describe` | Ask the AI to describe the project |

Example:

```bash
python3 export_project_prompt.py --mode describe
```

---

## Install for Global Use

### macOS / Linux

```bash
chmod +x export_project_prompt.py
mkdir -p ~/.local/bin
cp export_project_prompt.py ~/.local/bin/export-project-prompt
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Now you can run it anywhere:

```bash
export-project-prompt
```

### Windows

1. Save the file in `C:\Users\<you>\bin`
2. Create a `export-project-prompt.bat` next to it:

   ```bat
   @echo off
   python "%~dp0export_project_prompt.py" %*
   ```
3. Add that folder to your PATH
   Then run:

```bash
export-project-prompt
```

---

## Requirements

* Python 3.7+
* `pbcopy` (macOS), `xclip/xsel` (Linux), or `clip` (Windows) for clipboard support


