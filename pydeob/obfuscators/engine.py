import random
import logging
from pathlib import Path
from typing import List, Optional
from pydeob.obfuscators.base import (
    Base64Obfuscator, ZlibObfuscator, 
    ReverseObfuscator, XorObfuscator, 
    LambdaObfuscator, GzipObfuscator,
    MarshalObfuscator, JunkCodeObfuscator,
    PyArmorObfuscator, NuitkaObfuscator
)

logger = logging.getLogger(__name__)

class ObfuscationEngine:
    def __init__(self, allowed_methods: Optional[List[str]] = None):
        all_obfuscators = [
            Base64Obfuscator(),
            ZlibObfuscator(),
            ReverseObfuscator(),
            XorObfuscator(),
            LambdaObfuscator(),
            GzipObfuscator(),
            MarshalObfuscator(),
            JunkCodeObfuscator(),
            PyArmorObfuscator(),
            NuitkaObfuscator()
        ]
        
        if allowed_methods:
            self.obfuscators = [o for o in all_obfuscators if o.name in allowed_methods]
            if not self.obfuscators:
                raise ValueError(f"No valid obfuscators found for methods: {allowed_methods}")
        else:
            self.obfuscators = all_obfuscators

    def obfuscate(self, source: str, iterations: int) -> str:
        current_source = source
        logger.info(f"Starting obfuscation with {iterations} iterations...")
        
        for i in range(iterations):
            obfuscator = random.choice(self.obfuscators)
            logger.debug(f"Iteration {i+1}: Applying {obfuscator.name}")
            current_source = obfuscator.obfuscate(current_source)
            
        return current_source
