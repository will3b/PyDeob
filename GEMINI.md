# PyDeob Project Instructions

## Coding Standards
- Use Python 3.12+ features (dataclasses, type hints).
- Follow SOLID principles.
- Use `rich` for CLI output.
- All new decoders should inherit from `BaseDecoder`.

## Testing
- Use `pytest` for unit and integration tests.
- Maintain tests in the `tests/` directory.
- Verify new decoders with sample obfuscated scripts.

## Directory Structure
- `pydeob/`: Main package.
- `pydeob/decoders/`: Decoder plugins.
- `pydeob/analyzers/`: AST analysis logic.
- `pydeob/hooks/`: Sandboxing and execution hooks.
- `pydeob/extractors/`: IOC extraction.
- `pydeob/reporters/`: Reporting modules.
- `output/`: Default directory for intermediate layers and reports.

## Adding Decoders
- Add new decoder classes to relevant modules in `pydeob/decoders/`.
- Register the new decoder class in `pydeob/plugins/__init__.py`.
