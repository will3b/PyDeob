import base64
from pathlib import Path
from pydeob.engine import DeobfuscationEngine

def test_exec_b64_peeling(tmp_path):
    original_code = "print('hello from exec')"
    encoded_payload = base64.b64encode(original_code.encode()).decode()
    obfuscated_code = f"import base64\nexec(base64.b64decode('{encoded_payload}'))"
    
    test_file = tmp_path / "test_exec.py"
    test_file.write_text(obfuscated_code)
    
    output_dir = tmp_path / "output"
    engine = DeobfuscationEngine(output_dir=output_dir)
    report = engine.analyze(test_file)
    
    assert len(report.layers) == 2
    assert report.layers[1].source == original_code
    assert report.layers[1].decoder_name == "exec_base64"
    assert "base64" in report.imports
