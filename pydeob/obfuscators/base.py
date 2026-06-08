import base64
import zlib
import random
import string
import gzip
import marshal
import subprocess
import tempfile
import shutil
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List

class BaseObfuscator(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def obfuscate(self, source: str) -> str:
        pass

class Base64Obfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "base64_exec"

    def obfuscate(self, source: str) -> str:
        encoded = base64.b64encode(source.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{encoded}'))"

class ZlibObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "zlib_exec"

    def obfuscate(self, source: str) -> str:
        compressed = zlib.compress(source.encode())
        return f"import zlib\nexec(zlib.decompress({compressed!r}))"

class ReverseObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "reverse_exec"

    def obfuscate(self, source: str) -> str:
        reversed_source = source[::-1]
        return f"exec({reversed_source!r}[::-1])"

class XorObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "xor_exec"

    def obfuscate(self, source: str) -> str:
        key = random.randint(1, 255)
        encoded = "".join(chr(ord(c) ^ key) for c in source)
        return f"exec(''.join(chr(ord(c) ^ {key}) for c in {encoded!r}))"

class LambdaObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "lambda_zlib_b64"

    def obfuscate(self, source: str) -> str:
        compressed = zlib.compress(source.encode())
        encoded = base64.b64encode(compressed).decode()[::-1]
        var_name = "".join(random.choices(string.ascii_letters, k=1))
        return f"{var_name} = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));\nexec(({var_name})('{encoded}'))"

class GzipObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "gzip_exec"

    def obfuscate(self, source: str) -> str:
        compressed = gzip.compress(source.encode())
        return f"import gzip\nexec(gzip.decompress({compressed!r}))"

class MarshalObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "marshal_exec"

    def obfuscate(self, source: str) -> str:
        code_obj = compile(source, "<obfuscated>", "exec")
        dumped = marshal.dumps(code_obj)
        return f"import marshal\nexec(marshal.loads({dumped!r}))"

class JunkCodeObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "junk_code"

    def obfuscate(self, source: str) -> str:
        junk_vars = ["".join(random.choices(string.ascii_letters, k=8)) for _ in range(3)]
        junk_lines = [
            f"{junk_vars[0]} = {random.randint(1, 1000)}",
            f"{junk_vars[1]} = '{''.join(random.choices(string.ascii_letters, k=10))}'",
            f"if {random.randint(0, 1)} == {random.randint(2, 3)}: {junk_vars[2]} = True"
        ]
        random.shuffle(junk_lines)
        return "\n".join(junk_lines) + "\n" + source

class PyArmorObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "pyarmor_exec"

    def obfuscate(self, source: str) -> str:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            script_file = tmp_path / "target.py"
            script_file.write_text(source)
            try:
                subprocess.run(["pyarmor", "gen", str(script_file)], 
                               cwd=tmpdir, check=True, capture_output=True)
                output_file = tmp_path / "dist" / "target.py"
                if output_file.exists():
                    return output_file.read_text()
                else:
                    return f"# [PyDeob] PyArmor failed to generate output. Ensure 'pyarmor' is installed.\n{source}"
            except Exception as e:
                return f"# [PyDeob] PyArmor error: {e}\n{source}"

class NuitkaObfuscator(BaseObfuscator):
    @property
    def name(self) -> str:
        return "nuitka_exec"

    def obfuscate(self, source: str) -> str:
        # Simulate Nuitka internal markers to test detection
        return f"# [PyDeob] Nuitka simulation\nimport sys\nif not hasattr(sys, '__nuitka_binary_dir'): pass\n{source}"
