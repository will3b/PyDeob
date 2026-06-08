import ast
from abc import ABC, abstractmethod
from typing import Optional, Union

class BaseDecoder(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """The unique name of the decoder."""
        pass

    def detect_string(self, source: str) -> bool:
        """
        Detect if this decoder can handle the raw string.
        Override this for string-based decoders.
        """
        return False

    def decode_string(self, source: str) -> Optional[str]:
        """
        Decode the raw string.
        Returns the decoded string or None if it fails.
        """
        return None

    def visit_ast(self, node: ast.AST) -> Optional[Union[ast.AST, str]]:
        """
        Visit an AST node and return a transformed node or a decoded string.
        Override this for AST-based decoders.
        """
        return None
