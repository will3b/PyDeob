from typing import Optional
from pydeob.decoders.base import BaseDecoder

class ReverseDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "reverse"

    def detect_string(self, source: str) -> bool:
        # Heuristic: if it's a raw string that looks like it might be reversed 
        # (e.g. starts with '==' or ends with 'tropmi')
        source = source.strip()
        if not source:
            return False
        
        # Check for reversed base64 padding
        if source.startswith("==") or source.startswith("="):
            return True
            
        # Check for reversed imports
        if "tropmi" in source:
            return True
            
        return False

    def decode_string(self, source: str) -> Optional[str]:
        return source[::-1]
