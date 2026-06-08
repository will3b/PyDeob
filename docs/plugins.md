# PyDeob Plugin Development Guide

PyDeob is designed to be easily extended with new decoders.

## Creating a New Decoder

1.  **Inherit from `BaseDecoder`**:
    Create a new class in `pydeob/decoders/` (or a sub-module) that inherits from `pydeob.decoders.base.BaseDecoder`.

2.  **Implement `name`**:
    Provide a unique string name for your decoder.

3.  **Implement `detect_string` and `decode_string`** (Optional):
    If your decoder works on raw strings, implement these methods.

4.  **Implement `visit_ast`** (Optional):
    If your decoder targets AST patterns, implement this method. It should return a string (the recovered source code) if a transformation is possible.

## Example: Simple String Reversal Decoder

```python
from pydeob.decoders.base import BaseDecoder
from typing import Optional

class ReverseDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "reverse"

    def detect_string(self, source: str) -> bool:
        # Heuristic: check if it looks reversed (e.g., ends with 'tropmi')
        return source.strip().endswith("tropmi")

    def decode_string(self, source: str) -> Optional[str]:
        return source[::-1]
```

## Registering the Plugin

Currently, plugins are manually added to the list in `pydeob/plugins/__init__.py`. In the future, this will be replaced with an automatic entry-point discovery system.
