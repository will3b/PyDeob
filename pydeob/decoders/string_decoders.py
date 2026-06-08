import base64
import binascii
import codecs
import re
from typing import Optional
from pydeob.decoders.base import BaseDecoder

class Base64Decoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "base64"

    def detect_string(self, source: str) -> bool:
        # Very loose detection, better to check for common patterns or padding
        # We look for a string that looks like base64 and has at least some length
        source = source.strip()
        if not source or len(source) < 8:
            return False
        # Only allow base64 chars
        if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', source):
            return False
        return True

    def decode_string(self, source: str) -> Optional[str]:
        try:
            decoded = base64.b64decode(source.strip(), validate=True)
            try:
                return decoded.decode('utf-8')
            except UnicodeDecodeError:
                # Might be binary, return as repr or hex if we want to continue, 
                # but for now let's assume we want source code
                return None
        except Exception:
            return None

class HexDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "hex"

    def detect_string(self, source: str) -> bool:
        source = source.strip()
        if not source or len(source) < 8 or len(source) % 2 != 0:
            return False
        if not re.fullmatch(r'[0-9a-fA-F]+', source):
            return False
        return True

    def decode_string(self, source: str) -> Optional[str]:
        try:
            decoded = binascii.unhexlify(source.strip())
            return decoded.decode('utf-8')
        except Exception:
            return None

class ROT13Decoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "rot13"

    def detect_string(self, source: str) -> bool:
        # Hard to detect without knowing it's ROT13.
        # Usually ROT13 is applied to code which makes it look weird.
        # For now, let's just allow manual trigger or very specific heuristics
        return False 

    def decode_string(self, source: str) -> Optional[str]:
        try:
            return codecs.encode(source, 'rot_13')
        except Exception:
            return None
