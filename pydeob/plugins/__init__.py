import importlib
import pkgutil
import logging
from typing import List, Type
from pydeob.decoders.base import BaseDecoder
import pydeob.decoders.string_decoders
import pydeob.decoders.compression_decoders
import pydeob.decoders.ast_decoders
import pydeob.decoders.reverse_decoder

logger = logging.getLogger(__name__)

def discover_decoders() -> List[BaseDecoder]:
    """
    Discover all decoder plugins.
    For now, we manually import the builtin ones, 
    but we can extend this to dynamic discovery in pydeob.plugins.*
    """
    decoders = []
    
    # List of modules to check
    modules = [
        pydeob.decoders.string_decoders,
        pydeob.decoders.compression_decoders,
        pydeob.decoders.ast_decoders,
        pydeob.decoders.reverse_decoder
    ]
    
    for module in modules:
        for name in dir(module):
            obj = getattr(module, name)
            if (isinstance(obj, type) and 
                issubclass(obj, BaseDecoder) and 
                obj is not BaseDecoder):
                decoders.append(obj())
                
    logger.debug(f"Discovered {len(decoders)} decoders: {[d.name for d in decoders]}")
    return decoders
