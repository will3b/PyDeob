import ast
import logging
from pathlib import Path
from typing import List, Optional, Union
from pydeob.models import AnalysisReport, Layer
from pydeob.plugins import discover_decoders
from pydeob.decoders.base import BaseDecoder

logger = logging.getLogger(__name__)

class DeobfuscationEngine:
    def __init__(self, base_output_dir: Path, use_sandbox: bool = False, extract_iocs: bool = False):
        self.base_output_dir = base_output_dir
        self.use_sandbox = use_sandbox
        self.extract_iocs = extract_iocs
        self.decoders = discover_decoders()
        self.sandbox = None
        if self.use_sandbox:
            from pydeob.hooks.sandbox import Sandbox
            self.sandbox = Sandbox()
        self.output_dir: Optional[Path] = None

    def analyze(self, file_path: Path) -> AnalysisReport:
        # Create a subfolder for this specific script
        script_folder_name = file_path.stem
        self.output_dir = self.base_output_dir / script_folder_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        source = file_path.read_text()
        report = AnalysisReport(target_file=str(file_path))
        report.add_layer(source, decoder_name="original")
        self._save_layer(report.layers[0])

        current_source = source
        iteration = 0
        max_iterations = 50

        while iteration < max_iterations:
            iteration += 1
            logger.info(f"Peeling layer iteration {iteration}...")
            
            result = self._try_peel(current_source, report)
            
            if result:
                transformed_source, decoder_name = result
                report.add_layer(transformed_source, decoder_name=decoder_name)
                self._save_layer(report.layers[-1])
                current_source = transformed_source
                logger.info(f"Recovered new layer {len(report.layers)-1} using '{decoder_name}'")
            else:
                logger.info("No more transformations possible.")
                break

        return report

    def _try_peel(self, source: str, report: AnalysisReport) -> Optional[tuple[str, str]]:
        # 1. Try AST decoders first (more precise)
        try:
            tree = ast.parse(source)
            from pydeob.analyzers.ast_analyzer import ASTAnalyzer
            analyzer = ASTAnalyzer(report)
            analyzer.analyze(tree)

            for node in ast.walk(tree):
                for decoder in self.decoders:
                    decoded = decoder.visit_ast(node)
                    if isinstance(decoded, str) and decoded != source:
                        return decoded, decoder.name
        except SyntaxError as e:
            logger.debug(f"AST parse failed: {e}")
            pass

        # 2. Try Sandbox if enabled
        if self.use_sandbox and self.sandbox:
            self.sandbox.payloads = [] # Clear payloads from previous run
            payloads = self.sandbox.run(source)
            for p in payloads:
                if p["type"] in ("exec", "eval", "compile") and p["payload"] != source:
                    return p["payload"], f"sandbox_{p['type']}"

        # 3. Try string decoders
        for decoder in self.decoders:
            if decoder.detect_string(source):
                decoded = decoder.decode_string(source)
                if decoded and decoded != source:
                    return decoded, decoder.name

        return None

    def _save_layer(self, layer: Layer):
        filename = f"layer_{layer.index:03d}.py"
        path = self.output_dir / filename
        path.write_text(layer.source)
        layer.output_path = str(path)
        logger.debug(f"Saved layer {layer.index} to {path}")
