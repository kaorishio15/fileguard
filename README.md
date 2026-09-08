# FileGuard — Static Threat & Risk Inspection Engine

**FileGuard** is a lightweight, stateless static file threat analyzer built in Python.

It inspects untrusted files for potential malware or phishing indicators **without executing them**. FileGuard analyzes file contents using security heuristics and produces a transparent, explainable threat score from **0 to 100** with supporting evidence.

## Features

* SHA-256 file hashing
* Shannon entropy analysis
* Magic-byte file type detection
* File extension mismatch detection
* Double-extension detection
* PDF JavaScript inspection
* ZIP archive inspection
* Explainable risk scoring and evidence
* Web dashboard with drag-and-drop uploads
* Command-line interface for local scanning
* Stateless, in-memory file processing

## Why Entropy Matters

Shannon entropy measures how random or unpredictable a file's binary data is on a scale from **0 to 8 bits per byte**.

Malware authors may use packing, encryption, or obfuscation to hide malicious code from traditional signature-based detection. These techniques can make file contents appear highly random, resulting in higher entropy.

FileGuard uses high entropy as a **heuristic**, not proof of malware. Legitimate compressed or encrypted files can also have high entropy, so this signal is combined with other indicators when calculating the final risk score.

## Project Structure

```text
fileguard/
├── app.py              # Flask web server and CLI entry point
├── engine.py           # Static analysis and risk scoring engine
├── requirements.txt    # Project dependencies
├── vercel.json         # Vercel deployment configuration
└── templates/
    └── index.html      # Web dashboard
```

## How It Works

```text
User File
    │
    ├── Web Upload → POST /api/scan
    │
    └── CLI → python app.py scan <file>
                        │
                        ▼
                    engine.py
                        │
        ┌───────────────┼───────────────┐
        │               │               │
    SHA-256        Magic Bytes       Entropy
    Extensions     PDF Analysis      ZIP Inspection
        │               │               │
        └───────────────┼───────────────┘
                        │
                        ▼
                   Risk Engine
                        │
                        ▼
              Score + Severity + Evidence
```

## Getting Started

### Prerequisites

* Python 3.8+
* Git

### Installation

```powershell
git clone https://github.com/your-username/fileguard.git
cd fileguard

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## Running Locally

Start the Flask application:

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Command-Line Usage

Scan a file directly from the terminal:

```powershell
python app.py scan test_files/urgent_invoice.pdf.exe
```

The CLI returns the file's detected type, SHA-256 hash, entropy, risk score, severity level, and supporting security indicators.

## Testing

Run the test suite with:

```powershell
pytest -v
```

## Future Improvements

* YARA rule integration
* VirusTotal hash lookups
* PE executable header analysis
* Additional file format support
* Client-side file size validation

## Disclaimer

FileGuard is a **static heuristic analysis tool**. A high risk score does not guarantee that a file is malicious, and a low risk score does not guarantee that a file is safe.

It should be used as an additional security inspection tool rather than a replacement for antivirus software, endpoint protection, or professional malware analysis.
