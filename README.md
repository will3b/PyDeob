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

### Deep Obfuscation Guide

PyDeob includes a powerful offensive engine designed to test the limits of your deobfuscation capabilities.

#### Basic Usage
```bash
pydeob obfuscate malware.py --iterations 10
```

#### Advanced Options
| Option | Description |
| :--- | :--- |
| `file` | The source Python script to protect. |
| `--iterations` | Number of recursive protection layers (supports 1-100+). |
| `--methods` | Comma-separated list of specific engines to use (e.g., `--methods xor_exec,marshal_exec`). |
| `--output` | Custom name for the protected file (Default: `obfuscated_<original>.py`). |
| `--verbose` | Detailed logs showing which protection module was applied at each layer. |

#### Available Protection Modules
The engine randomly selects from these high-intensity modules at every iteration:

1. **`marshal_exec`**: Compiles source code to **Python Bytecode**. This hides the source logic entirely behind binary blobs.
2. **`lambda_zlib_b64`**: A multi-stage wrapper that uses dynamic lambdas and reversed strings to bypass static analysis.
3. **`xor_exec`**: Encrypts the code with a **dynamic XOR key** generated randomly for every layer.
4. **`zlib_exec` / `gzip_exec`**: High-ratio compression modules that shrink the payload and hide plain-text strings.
5. **`junk_code`**: Injects randomized "dead code" (junk variables, impossible if-statements) to increase analysis noise.
6. **`base64_exec`**: Standard encoding layer to facilitate transport and nesting.
7. **`reverse_exec`**: Inverts the string order to break simple pattern-matching decoders.

---

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
