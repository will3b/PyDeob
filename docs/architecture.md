# PyDeob Architecture

PyDeob is built as an extensible, iterative peeling engine for Python script analysis.

## Core Components

### 1. Deobfuscation Engine (`pydeob/engine.py`)
The heart of the framework. It orchestrates the peeling process by:
- Loading all available plugins.
- Iteratively attempting to transform the source code using both AST-based and string-based decoders.
- Saving intermediate layers for manual inspection.
- Running the static analyzer on each layer to accumulate indicators.

### 2. Plugin System (`pydeob/decoders/`)
Decoders are divided into categories:
- **String Decoders**: Operate on raw strings (e.g., Base64, Hex).
- **Compression Decoders**: Handle decompression (e.g., Zlib, Gzip).
- **AST Decoders**: Target specific code patterns (e.g., `exec(base64.b64decode(...))`, XOR loops).

### 3. AST Analyzer (`pydeob/analyzers/ast_analyzer.py`)
Uses the `ast` module to:
- Discover imports, functions, and classes.
- Detect behavioral indicators (e.g., `subprocess`, `socket`).
- Calculate a weighted risk score.
- Extract strings for IOC analysis.

### 4. Safe Dynamic Sandbox (`pydeob/hooks/sandbox.py`)
Provides a restricted execution environment where:
- Sensitive builtins like `exec`, `eval`, and `compile` are overridden.
- `__import__` is hooked to monitor module access and allow only safe imports.
- Payloads passed to execution builtins are captured as new layers.

### 5. Reporters (`pydeob/reporters/`)
Generates output in multiple formats:
- **Console**: Rich text output with tables.
- **JSON**: Structured data for automated processing.
- **Markdown**: Human-readable documentation of the findings.
