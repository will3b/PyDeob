import base64
from pathlib import Path
from pydeob.engine import DeobfuscationEngine

def test_base64_peeling(tmp_path):
    original_code = "print('hello world')"
    encoded_code = base64.b64encode(original_code.encode()).decode()
    
    test_file = tmp_path / "test.txt"
    test_file.write_text(encoded_code)
    
    output_dir = tmp_path / "output"
    engine = DeobfuscationEngine(output_dir=output_dir)
    report = engine.analyze(test_file)
    
    assert len(report.layers) == 2
    assert report.layers[0].source == encoded_code
    assert report.layers[1].source == original_code
    assert report.layers[1].decoder_name == "base64"
