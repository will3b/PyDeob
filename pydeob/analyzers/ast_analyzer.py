import ast
from typing import List, Set, Dict, Any
from pydeob.models import AnalysisReport, Indicator, Severity, IOC

class ASTAnalyzer(ast.NodeVisitor):
    def __init__(self, report: AnalysisReport):
        self.report = report
        self.imports: Set[str] = set()
        self.functions: Set[str] = set()
        self.classes: Set[str] = set()
        self.strings: List[str] = []
        
    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.functions.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.functions.add(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.classes.add(node.name)
        self.generic_visit(node)

    def analyze(self, tree: ast.AST):
        self.visit(tree)

        # Accumulate results into the report
        current_imports = set(self.report.imports)
        current_imports.update(self.imports)
        self.report.imports = sorted(list(current_imports))
        
        current_functions = set(self.report.functions)
        current_functions.update(self.functions)
        self.report.functions = sorted(list(current_functions))
        
        current_classes = set(self.report.classes)
        current_classes.update(self.classes)
        self.report.classes = sorted(list(current_classes))
        
        # Cap risk score
        if self.report.risk_score > 100:
            self.report.risk_score = 100

    BEHAVIORAL_INDICATORS = {
        "subprocess": (Severity.HIGH, 10, "Execution of external commands"),
        "socket": (Severity.MEDIUM, 5, "Network socket communication"),
        "requests": (Severity.LOW, 2, "HTTP requests"),
        "urllib": (Severity.LOW, 2, "HTTP requests"),
        "ctypes": (Severity.HIGH, 15, "Foreign function interface (often for memory injection)"),
        "winreg": (Severity.MEDIUM, 8, "Windows Registry access"),
        "psutil": (Severity.LOW, 3, "Process management/enumeration"),
        "os.system": (Severity.HIGH, 12, "Direct shell command execution"),
        "powershell": (Severity.CRITICAL, 20, "PowerShell execution"),
    }

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name)
            self._check_behavioral(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module)
            self._check_behavioral(node.module)
        self.generic_visit(node)

    def _check_behavioral(self, name: str):
        if name in self.BEHAVIORAL_INDICATORS:
            sev, weight, desc = self.BEHAVIORAL_INDICATORS[name]
            self.report.indicators.append(Indicator(
                name=f"Behavioral: {name}",
                description=desc,
                severity=sev
            ))
            self.report.risk_score += weight
            self.report.risk_explanation.append(f"Import of {name} detected ({desc})")

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.strings.append(node.value)
            # Extract IOCs from strings
            from pydeob.extractors.iocs import IOCExtractor
            extractor = IOCExtractor()
            iocs = extractor.extract(node.value)
            for ioc in iocs:
                if ioc not in self.report.iocs:
                    self.report.iocs.append(ioc)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Detect exec/eval
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("exec", "eval", "compile"):
            self.report.indicators.append(Indicator(
                name=f"Dynamic Execution: {func_name}",
                description=f"Detected use of {func_name}()",
                severity=Severity.MEDIUM,
                details={"line": node.lineno}
            ))
            self.report.risk_score += 2
            self.report.risk_explanation.append(f"Use of {func_name}() detected at line {node.lineno}")

        self.generic_visit(node)
