import zlib
import gzip
import bz2
import lzma
from typing import Optional
from pydeob.decoders.base import BaseDecoder

class ZlibDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "zlib"

    def detect_string(self, source: str) -> bool:
        # Zlib header is usually 78 9c or similar
        return False # Hard to detect from string unless it's hex/base64 encoded first

    def decode_string(self, source: str) -> Optional[str]:
        # Usually source would be bytes, but engine passes str.
        # This implies we might need a bridge if the output of one decoder is bytes.
        # For now, let's assume we might need to convert to bytes if it looks like it.
        try:
            # Try to treat source as latin-1 to preserve bytes if it was decoded from bytes
            data = source.encode('latin-1')
            decoded = zlib.decompress(data)
            return decoded.decode('utf-8')
        except Exception:
            return None

class GzipDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "gzip"

    def decode_string(self, source: str) -> Optional[str]:
        try:
            data = source.encode('latin-1')
            decoded = gzip.decompress(data)
            return decoded.decode('utf-8')
        except Exception:
            return None

class BZ2Decoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "bz2"

    def decode_string(self, source: str) -> Optional[str]:
        try:
            data = source.encode('latin-1')
            decoded = bz2.decompress(data)
            return decoded.decode('utf-8')
        except Exception:
            return None

class LZMADecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "lzma"

    def decode_string(self, source: str) -> Optional[str]:
        try:
            data = source.encode('latin-1')
            decoded = lzma.decompress(data)
            return decoded.decode('utf-8')
        except Exception:
            return None
