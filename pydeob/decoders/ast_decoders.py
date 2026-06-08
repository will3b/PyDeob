import ast
import base64
from typing import Optional, Union
from pydeob.decoders.base import BaseDecoder

class ExecBase64Decoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "exec_base64"

    def visit_ast(self, node: ast.AST) -> Optional[Union[ast.AST, str]]:
        """
        Looks for exec(base64.b64decode("..."))
        """
        if not isinstance(node, ast.Call):
            return None
        
        # Check if it's exec()
        if not (isinstance(node.func, ast.Name) and node.func.id == "exec"):
            return None
            
        if len(node.args) != 1:
            return None
            
        arg = node.args[0]
        
        # Check if arg is base64.b64decode(...)
        if isinstance(arg, ast.Call):
            func = arg.func
            if isinstance(func, ast.Attribute) and func.attr == "b64decode":
                if len(arg.args) == 1 and isinstance(arg.args[0], ast.Constant):
                    payload = arg.args[0].value
                    try:
                        decoded = base64.b64decode(payload).decode('utf-8')
                        return decoded
                    except Exception:
                        pass
            elif isinstance(func, ast.Name) and func.id == "b64decode":
                if len(arg.args) == 1 and isinstance(arg.args[0], ast.Constant):
                    payload = arg.args[0].value
                    try:
                        decoded = base64.b64decode(payload).decode('utf-8')
                        return decoded
                    except Exception:
                        pass
class XorDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "xor"

    def visit_ast(self, node: ast.AST) -> Optional[Union[ast.AST, str]]:
        # Detect "".join(chr(ord(c) ^ key) for c in "...")
        if not isinstance(node, ast.Call):
            return None
        
        # Check for "".join(...) or similar
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "join"):
            return None
            
        if len(node.args) != 1 or not isinstance(node.args[0], (ast.ListComp, ast.GeneratorExp)):
            return None
            
        comp = node.args[0]
        # Check if it's chr(ord(x) ^ key)
        if not isinstance(comp.elt, ast.Call) or not (isinstance(comp.elt.func, ast.Name) and comp.elt.func.id == "chr"):
            return None
            
        if len(comp.elt.args) != 1 or not isinstance(comp.elt.args[0], ast.BinOp):
            return None
            
        binop = comp.elt.args[0]
        if not isinstance(binop.op, ast.BitXor):
            return None
            
        # Left side should be ord(x)
        if not isinstance(binop.left, ast.Call) or not (isinstance(binop.left.func, ast.Name) and binop.left.func.id == "ord"):
            return None
            
        # Right side should be a constant (the key)
        if not isinstance(binop.right, ast.Constant) or not isinstance(binop.right.value, int):
            return None
            
        key = binop.right.value
        
        # Now find the source data in generators
        if len(comp.generators) != 1:
            return None
            
        gen = comp.generators[0]
        if not isinstance(gen.iter, ast.Constant) or not isinstance(gen.iter.value, str):
            return None
            
        encoded_str = gen.iter.value
        try:
            decoded = "".join(chr(ord(c) ^ key) for c in encoded_str)
            return f"'{decoded}'" # Return as a string literal representation
        except Exception:
            return None
class MarshalDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "marshal"

    def visit_ast(self, node: ast.AST) -> Optional[Union[ast.AST, str]]:
        # Detect marshal.loads(b"...")
        if not isinstance(node, ast.Call):
            return None
            
        func = node.func
        is_marshal_loads = False
        if isinstance(func, ast.Attribute) and func.attr == "loads" and isinstance(func.value, ast.Name) and func.value.id == "marshal":
            is_marshal_loads = True
        elif isinstance(func, ast.Name) and func.id == "loads": # If imported as from marshal import loads
            is_marshal_loads = True
            
        if is_marshal_loads and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, bytes):
            payload = node.args[0].value
            # We can't easily turn marshal bytes to source code statically without uncompyle6
            # For now, we'll return a marker and the engine can treat it as a new "layer" 
            # (though it might not be valid python if we just return the bytes)
            # Better to return a disassembly or just the fact we found it.
            # But the engine wants a string to continue.
            # Let's return a comment with the hex dump and a warning.
            return f"# Marshal payload detected (len={len(payload)})\n# Hex: {payload.hex()[:100]}..."
            
        return None

class NestedExecDecoder(BaseDecoder):
    @property
    def name(self) -> str:
        return "nested_exec"

    def visit_ast(self, node: ast.AST) -> Optional[Union[ast.AST, str]]:
        # Detect exec("exec(...)")
        if not isinstance(node, ast.Call):
            return None
            
        if not (isinstance(node.func, ast.Name) and node.func.id == "exec"):
            return None
            
        if len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            payload = node.args[0].value.strip()
            if payload.startswith("exec(") or payload.startswith("eval("):
                return payload
        return None
