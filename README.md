# PyDeob

**PyDeob** is a production-quality, extensible Python deobfuscation and malware-analysis framework. It is designed to safely "peel" through multiple layers of obfuscation, recovering the original source code while identifying behavioral indicators and extracting Indicators of Compromise (IOCs).

## Key Features

- **Iterative Peeling Engine**: Automatically detects and applies transformations, iterating until the final payload is reached.
- **Hybrid Plugin Pipeline**: Combines **AST-based** pattern matching (precise) with **String-based** transformations (flexible).
- **Safe Dynamic Sandbox**: Intercepts `exec`, `eval`, and `compile` calls in a persistent restricted namespace, allowing complex multi-stage deobfuscators to work without ever executing malicious payloads on your host.
- **Advanced Protection Detection**: Specific signatures to identify high-level protections like **PyArmor** and **Nuitka**.

### Behavioral Scoring & Detection

PyDeob identifies usage of high-risk modules and advanced protection tools:

| Category | Protection / Module | Severity | Risk Weight |
| :--- | :--- | :--- | :--- |
| **Advanced** | **Nuitka** | **CRITICAL** | **+60** |
| **Advanced** | **PyArmor** | **CRITICAL** | **+50** |
| **System** | `powershell`, `os.system` | **CRITICAL/HIGH**| **+20/12** |
| **Execution** | `subprocess`, `ctypes` | **HIGH** | **+10/15** |
| **Dynamic** | `exec`, `eval`, `compile` | **MEDIUM** | **+2** |
| **Network** | `socket`, `requests`, `urllib` | **MEDIUM/LOW** | **+5/2** |

#### Why Nuitka and PyArmor are Critical
- **Nuitka**: This tool translates Python scripts into C++ and compiles them into a native machine-code binary. Deobfuscating Nuitka-protected code is extremely complex as it removes the original Python bytecode entirely.
- **PyArmor**: A professional tool that encrypts Python scripts and protects them with a custom runtime. It uses dynamic code generation and custom interpreters to prevent reverse engineering.

---

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
git clone https://github.com/will3b/PyDeob.git
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

1. **`pyarmor_exec`**: Calls external **PyArmor** (if installed) to encrypt the script.
2. **`nuitka_exec`**: Simulates **Nuitka** markers to test detection signatures.
3. **`marshal_exec`**: Compiles source code to **Python Bytecode**.
4. **`lambda_zlib_b64`**: Multi-stage dynamic lambda protection.
5. **`xor_exec`**: Dynamic XOR encryption.
6. **`zlib_exec` / `gzip_exec`**: High-ratio binary compression.
7. **`junk_code`**: Randomized "dead code" and noise injection.
8. **`base64_exec`**: Standard encoding layer.
9. **`reverse_exec`**: String order inversion.

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
