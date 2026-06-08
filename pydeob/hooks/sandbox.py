import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class Sandbox:
    def __init__(self):
        self.payloads: List[Dict[str, Any]] = []
        self.restricted_globals = {
            "exec": self._hook_exec,
            "eval": self._hook_eval,
            "compile": self._hook_compile,
            "__import__": self._hook_import,
            "__builtins__": {
                "exec": self._hook_exec,
                "eval": self._hook_eval,
                "compile": self._hook_compile,
                "__import__": self._hook_import,
                # Include some safe builtins if needed
                "print": print,
                "len": len,
                "ord": ord,
                "chr": chr,
                "range": range,
                "str": str,
                "int": int,
                "list": list,
                "dict": dict,
                "set": set,
                "tuple": tuple,
                "bool": bool,
                "bytes": bytes,
                "bytearray": bytearray,
                "enumerate": enumerate,
                "zip": zip,
                "map": map,
                "filter": filter,
                "any": any,
                "all": all,
                "sum": sum,
                "min": min,
                "max": max,
                "abs": abs,
                "round": round,
                "pow": pow,
                "divmod": divmod,
                "getattr": getattr,
                "setattr": setattr,
                "hasattr": hasattr,
                "delattr": delattr,
                "isinstance": isinstance,
                "issubclass": issubclass,
                "callable": callable,
                "type": type,
                "id": id,
                "hash": hash,
                "repr": repr,
                "ascii": ascii,
                "format": format,
                "vars": vars,
                "dir": dir,
                "locals": locals,
                "globals": globals,
            }
        }

    def _safe_decode(self, data: Any) -> str:
        if isinstance(data, str):
            return data
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return data.decode('latin-1')
        return str(data)

    def _hook_exec(self, source, globals=None, locals=None):
        logger.info(f"Intercepted exec() call")
        self.payloads.append({
            "type": "exec",
            "payload": self._safe_decode(source),
            "locals": str(locals) if locals else None
        })

    def _hook_eval(self, source, globals=None, locals=None):
        logger.info(f"Intercepted eval() call")
        self.payloads.append({
            "type": "eval",
            "payload": self._safe_decode(source),
            "locals": str(locals) if locals else None
        })
        return None 

    def _hook_compile(self, source, filename, mode, flags=0, dont_inherit=False, optimize=-1):
        logger.info(f"Intercepted compile() call")
        self.payloads.append({
            "type": "compile",
            "payload": self._safe_decode(source),
            "filename": filename,
            "mode": mode
        })
        return compile("None", "<sandbox>", "exec")

    def _hook_import(self, name, globals=None, locals=None, fromlist=(), level=0):
        logger.info(f"Intercepted __import__({name})")
        self.payloads.append({
            "type": "import",
            "name": name,
            "fromlist": fromlist
        })
        
        # Allow some safe modules for deobfuscation
        safe_modules = {"base64", "zlib", "bz2", "lzma", "gzip", "marshal", "binascii", "codecs", "string", "re"}
        if name in safe_modules:
            import importlib
            return importlib.import_module(name)
            
        return None

    def run(self, source: str):
        """
        Run the source code in a restricted namespace with our hooks.
        """
        try:
            # We use exec() to run the source in our restricted namespace
            exec(source, self.restricted_globals)
        except Exception as e:
            logger.debug(f"Sandbox execution halted: {e}")
        
        return self.payloads
