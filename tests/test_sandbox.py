from pydeob.engine import DeobfuscationEngine

def test_sandbox_peeling(tmp_path):
    # This code uses a dynamic calculation to bypass simple AST decoders
    obfuscated_code = """
import base64
cmd = base64.b64decode("cHJpbnQoJ2hlbGxvIGZyb20gc2FuZGJveCcp").decode()
exec(cmd)
"""
    
    test_file = tmp_path / "test_sandbox.py"
    test_file.write_text(obfuscated_code)
    
    output_dir = tmp_path / "output"
    # Enable sandbox
    engine = DeobfuscationEngine(output_dir=output_dir, use_sandbox=True)
    report = engine.analyze(test_file)
    
    # It should detect 'print('hello from sandbox')' via exec() hook
    assert len(report.layers) >= 2
    # Find the layer recovered by sandbox
    sandbox_layers = [l for l in report.layers if l.decoder_name == "sandbox_exec"]
    assert len(sandbox_layers) > 0
    assert "hello from sandbox" in sandbox_layers[0].source
