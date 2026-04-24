# DATA PREP

**Version:** v0.2 (April 22, 2026)
**Audience:** DIB contractors, C3PAO assessors, MSP consultants.
**Purpose:** Explain how to convert binary evidence formats (`.docx`,
`.pdf`, `.xlsx`) into the flat text files the stdlib-only engine
requires, without ever pointing the engine itself at a non-text input.

---

## Why this document exists

Hardseal AI-Detection is stdlib-only. It opens files as UTF-8 text.
Pointing the engine at a `.pdf`, `.docx`, or `.xlsx` will raise
`UnicodeDecodeError` and exit non-zero. That failure mode would
embarrass the tool on a first C3PAO demo. This document closes that
gap by treating evidence-prep as an explicit, documented,
outside-the-engine step.

The zero-dependency philosophy is not negotiable. It is the reason a
C3PAO can audit the tool in an afternoon and a contractor can run it
inside a CUI enclave without internet. Adding a PDF parser to the
engine would violate that posture. So the engine stays strict. The
prep step is yours to run with tools you trust.

---

## Supported inputs (no prep needed)

The engine reads anything that is valid UTF-8 text:

- `.txt`, `.md`, `.markdown`
- `.csv`, `.tsv`
- `.log`, `.json`, `.yaml`, `.xml`
- Any plain text file regardless of extension

---

## Inputs that require prep

| Format | Why it fails | Prep tool (recommended) |
|---|---|---|
| `.pdf` | Binary | `pdftotext` (poppler-utils) |
| `.docx` | ZIP containing XML | `pandoc` or stdlib-only script below |
| `.xlsx` | ZIP containing XML | `xlsx2csv` or Excel export to `.csv` |
| `.rtf` | Proprietary markup | `pandoc` |
| `.png`, `.jpg`, `.tif` (scanned) | Image; needs OCR | `tesseract-ocr` |
| `.eml`, `.msg` | Email container | `emldump` or `msgextract` |

---

## Security posture for prep tools

Prep tools run **outside** the engine, in a separate step, on the same
machine where your evidence lives.

**Do:**
- Run prep tools locally on the workstation or in the CUI enclave.
- Log the prep command and its input/output file paths in your
  evidence chain (C3PAOs ask: "what did you do to this artifact
  before submitting it?").
- Keep the original binary file alongside the prepped `.txt`. Do not
  discard the original.
- Use vendor-signed binaries. For Windows, use the installer from
  the tool's official site. For Linux, use your distribution's
  package manager. For macOS, use Homebrew or the official `.pkg`.

**Don't:**
- Upload CUI to a cloud-based `.pdf`-to-`.txt` service. That is a
  3.1.3 (CUI flow control) violation regardless of how convenient the
  web UI looks.
- Run prep tools with elevated privileges. Text conversion does not
  need root.
- Point the Hardseal engine at an unverified `.txt` output without
  reviewing it first. Some converters emit garbled text on
  password-protected or image-only PDFs; that garbled text can
  produce confusing scores.

---

## Conversion recipes

### PDF: `pdftotext` (recommended)

Install:
```
# macOS
brew install poppler

# Ubuntu / Debian
sudo apt install poppler-utils

# RHEL / Fedora
sudo dnf install poppler-utils
```

Convert:
```
pdftotext -layout input.pdf input.txt
```

The `-layout` flag preserves column and table structure, which matters
for audit logs and access reviews. Without it, multi-column PDFs
interleave unpredictably.

### PDF: stdlib-only fallback (no network, no install)

If you are in a true air-gapped CUI enclave and cannot install
`poppler-utils`, extract PDF text using a minimal Python helper
invoking a system-preinstalled tool, or fall back to printing the
PDF to a text-rendering print-to-file driver. Most Windows and macOS
systems have this built in. Do not use pip-installed PDF libraries
inside the enclave unless they are pre-vetted by your security team.

### DOCX: `pandoc` (recommended)

Install:
```
# macOS
brew install pandoc

# Ubuntu / Debian
sudo apt install pandoc
```

Convert:
```
pandoc input.docx -t plain -o input.txt
```

The `-t plain` output format strips styling and keeps heading
structure readable, which preserves the section hierarchy the engine
uses in citation-graph analysis.

### DOCX: stdlib-only fallback

A `.docx` is a ZIP archive containing `word/document.xml`. You can
extract the text with stdlib only:

```python
import zipfile, re, sys

def docx_to_text(path):
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    # Strip tags. For real production prep, use pandoc.
    text = re.sub(r"<[^>]+>", " ", xml)
    text = re.sub(r"\s+", " ", text).strip()
    return text

if __name__ == "__main__":
    for p in sys.argv[1:]:
        out = p.rsplit(".", 1)[0] + ".txt"
        with open(out, "w", encoding="utf-8") as f:
            f.write(docx_to_text(p))
        print(f"wrote {out}")
```

This loses formatting and may mangle inline footnotes. `pandoc` is
strongly preferred. This fallback is for enclaves where nothing
except Python is installable.

### XLSX: CSV export

The simplest path is to open the workbook in Excel / LibreOffice
Calc and "Save As CSV" one sheet at a time. The engine reads CSV
natively.

CLI path:
```
# macOS / Linux
pip install --user xlsx2csv
xlsx2csv input.xlsx input.csv
```

### Scanned PDFs and images: `tesseract`

If the PDF is a scan rather than a text-based PDF, `pdftotext` will
produce empty output. Run OCR first:

```
# Install
brew install tesseract    # macOS
sudo apt install tesseract-ocr   # Debian

# Convert PDF pages to images, then OCR each page
# (requires poppler's pdftoppm)
pdftoppm -r 300 scan.pdf page
for img in page-*.ppm; do
  tesseract "$img" "${img%.ppm}" -l eng
done
cat page-*.txt > scan.txt
```

Label the resulting `.txt` as OCR-derived. Hardseal's engine has no
way to know the text was OCRed; if the accuracy is poor the scores
will be misleading.

---

## After conversion: normalize file layout

The engine walks a packet directory and reads every file with a text
extension. Recommended directory layout after prep:

```
packet/
  3.1.1_access_control.md        # hand-authored SSP narrative
  3.13.1_boundary_protection.md
  3.3.1_audit_records.md
  policy/
    AC-Policy.txt                # from pandoc of AC-Policy.docx
  logs/
    audit_export.csv             # from xlsx2csv
  procedures/
    incident_response.txt        # from pdftotext
```

The engine does not require this exact layout, but every file must be
UTF-8 text.

---

## Running the engine after prep

Standard invocation:

```
python3 mismatch_engine_ai.py packet/ --json > findings.json
```

If you get `UnicodeDecodeError` at runtime, check the file listed in
the traceback. It is almost certainly a binary you missed. Prep it
and re-run.

---

## Prep-chain logging

For C3PAO audit readiness, keep a `prep_log.txt` next to every
packet you submit:

```
2026-04-22T14:32:11Z  pdftotext -layout access_policy.pdf access_policy.txt   # sha256(input)=abcd1234  sha256(output)=9f8e7d6c
2026-04-22T14:32:45Z  pandoc ir_runbook.docx -t plain -o ir_runbook.txt        # sha256(input)=...       sha256(output)=...
2026-04-22T14:33:02Z  python3 mismatch_engine_ai.py packet/ --json > findings.json
```

Every prep tool invocation should be logged with a timestamp, the
input and output sha256 hashes, and the tool + flags used. This is
the provenance trail an assessor will ask for: "what did you do to
this artifact between the source system and what we are looking at
now?"

---

## When to call the author

If your evidence format isn't listed here or your prep chain produces
output the engine flags in a way you can't explain, open an issue or
email rico@hardseal.ai with the tool chain you used and a redacted
excerpt of the output. Include the commitment hash
`32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf`
and the engine version.

---

*"Stdlib-only is a security differentiator, not a limitation. The
prep step is where you earn it."*
