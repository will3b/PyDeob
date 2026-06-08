from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Indicator:
    name: str
    description: str
    severity: Severity
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class IOC:
    type: str
    value: str
    context: Optional[str] = None

@dataclass
class Layer:
    index: int
    source: str
    decoder_name: Optional[str] = None
    output_path: Optional[str] = None

@dataclass
class AnalysisReport:
    target_file: str
    layers: List[Layer] = field(default_factory=list)
    indicators: List[Indicator] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    risk_score: int = 0
    risk_explanation: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)

    def add_layer(self, source: str, decoder_name: Optional[str] = None):
        idx = len(self.layers)
        self.layers.append(Layer(index=idx, source=source, decoder_name=decoder_name))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_file": self.target_file,
            "risk_score": self.risk_score,
            "risk_explanation": self.risk_explanation,
            "layers_count": len(self.layers),
            "indicators": [
                {"name": i.name, "severity": i.severity.value, "description": i.description}
                for i in self.indicators
            ],
            "iocs": [{"type": i.type, "value": i.value} for i in self.iocs],
            "imports": self.imports,
            "functions": self.functions,
            "classes": self.classes,
        }
