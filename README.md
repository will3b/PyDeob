# PyDeob

**PyDeob** is a production-quality, extensible Python deobfuscation and malware-analysis framework. It is designed to safely "peel" through multiple layers of obfuscation, recovering the original source code while identifying behavioral indicators and extracting Indicators of Compromise (IOCs).

## Key Features

- **Iterative Peeling Engine**: Automatically detects and applies transformations, iterating until the final payload is reached.
- **Hybrid Plugin Pipeline**: Combines **AST-based** pattern matching (precise) with **String-based** transformations (flexible).
- **Safe Dynamic Sandbox**: Intercepts `exec`, `eval`, and `compile` calls in a persistent restricted namespace, allowing complex multi-stage deobfuscators to work without ever executing malicious payloads on your host.
- **Behavioral Scoring**: Identifies usage of high-risk modules like `subprocess`, `ctypes`, `socket`, and `winreg`, assigning a risk score from 0 to 100.
- **IOC Extraction**: Automatically finds URLs, IPs, Domains, Email addresses, and Cryptocurrency wallets across all recovered code layers.

## System Requirements

- **Python**: 3.12 or higher (Uses advanced `ast` features and type hinting).
- **Operating System**: Cross-platform (Linux, macOS, Windows).
- **Dependencies**: 
    - `rich`: For the professional CLI interface and logging.
    - `pyyaml`: For potential future configuration support.
    - `pytest`: (Optional) For running the test suite.

## Installation

PyDeob requires Python 3.12+.

```bash
git clone https://github.com/willb3/PyDeob.git
cd PyDeob
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Usage Guide

### Basic Analysis
Run a simple pass over a script to see the risk score and behavioral indicators.
```bash
pydeob analyze malware.py
```

### Deep Deobfuscation (Sandbox Mode)
If a script uses complex dynamic calculations or nested `exec` chains (like many modern obfuscators), use the `--sandbox` flag.
```bash
pydeob analyze malware.py --sandbox
```

### Full Reporting & IOC Extraction
Generate comprehensive Markdown/JSON reports and extract all networking/system IOCs.
```bash
pydeob analyze malware.py --report --extract-iocs
```

### Command Line Options

| Option | Description |
| :--- | :--- |
| `file` | The target file to analyze. Can be a `.py` script or a raw text dump. |
| `--sandbox` | **(Highly Recommended)** Runs the script in a persistent, restricted environment. It intercepts dynamic execution calls to recover "hidden" layers. |
| `--report` | Saves a human-readable `report.md` and a machine-readable `report.json` in the output subfolder. |
| `--extract-iocs` | Scans all discovered code layers for IPs, URLs, Domains, etc. |
| `--output-dir` | Set the base directory for results (Default: `output/`). A subfolder named after the script is created inside. |
| `--verbose` | Shows detailed logs of the peeling process, intercepted calls, and plugin actions. |

## Output Structure

Results are organized into a script-specific folder:
```text
output/
└── malware/
    ├── layer_000.py   # Original file
    ├── layer_001.py   # First deobfuscated layer
    ├── layer_002.py   # ...
    ├── final.py       # Final recovered code
    ├── report.md      # Human-readable summary
    └── report.json    # Structured data
```

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Plugin Development Guide](docs/plugins.md)
