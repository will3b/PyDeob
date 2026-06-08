import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pydeob.models import AnalysisReport, Severity

class ConsoleReporter:
    def __init__(self, console: Console):
        self.console = console

    def report(self, report: AnalysisReport):
        self.console.print(Panel(f"[bold blue]Analysis Results for {report.target_file}[/bold blue]"))
        
        # Risk Score
        score_color = "green" if report.risk_score < 20 else "yellow" if report.risk_score < 50 else "red"
        self.console.print(f"Risk Score: [{score_color}]{report.risk_score}/100[/{score_color}]")
        
        # Layers
        self.console.print(f"\n[bold]Layers Recovered:[/bold] {len(report.layers)}")
        for layer in report.layers:
            decoder = layer.decoder_name or "original"
            self.console.print(f"  - Layer {layer.index:03d}: [cyan]{decoder}[/cyan]")

        # Indicators
        if report.indicators:
            table = Table(title="Behavioral Indicators")
            table.add_column("Indicator", style="magenta")
            table.add_column("Severity", style="bold")
            table.add_column("Description")
            
            for ind in report.indicators:
                color = "red" if ind.severity in (Severity.HIGH, Severity.CRITICAL) else "yellow" if ind.severity == Severity.MEDIUM else "blue"
                table.add_row(ind.name, f"[{color}]{ind.severity.value}[/{color}]", ind.description)
            self.console.print(table)

        # IOCs
        if report.iocs:
            table = Table(title="Extracted IOCs")
            table.add_column("Type", style="cyan")
            table.add_column("Value")
            
            for ioc in report.iocs:
                table.add_row(ioc.type, ioc.value)
            self.console.print(table)

        # Imports
        if report.imports:
            self.console.print(f"\n[bold]Imports:[/bold] {', '.join(report.imports)}")

class JSONReporter:
    def report(self, report: AnalysisReport, output_path: Path):
        data = report.to_dict()
        with open(output_path, "w") as f:
            json.dump(data, f, indent=4)

class MarkdownReporter:
    def report(self, report: AnalysisReport, output_path: Path):
        lines = [
            f"# PyDeob Analysis Report: {Path(report.target_file).name}",
            f"\n## Summary",
            f"- **Target File:** `{report.target_file}`",
            f"- **Risk Score:** {report.risk_score}/100",
            f"- **Layers Recovered:** {len(report.layers)}",
            f"\n## Decoding Chain",
        ]
        
        for layer in report.layers:
            lines.append(f"- Layer {layer.index:03d}: `{layer.decoder_name or 'original'}`")

        if report.indicators:
            lines.append("\n## Behavioral Indicators")
            lines.append("| Indicator | Severity | Description |")
            lines.append("|-----------|----------|-------------|")
            for ind in report.indicators:
                lines.append(f"| {ind.name} | {ind.severity.value} | {ind.description} |")

        if report.iocs:
            lines.append("\n## Extracted IOCs")
            lines.append("| Type | Value |")
            lines.append("|------|-------|")
            for ioc in report.iocs:
                lines.append(f"| {ioc.type} | {ioc.value} |")

        if report.imports:
            lines.append("\n## Imports")
            lines.append(", ".join([f"`{i}`" for i in report.imports]))

        output_path.write_text("\n".join(lines))
