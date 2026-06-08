import argparse
import sys
import logging
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler

from pydeob.engine import DeobfuscationEngine

console = Console()

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)]
    )

def main():
    parser = argparse.ArgumentParser(description="PyDeob: Extensible Python Deobfuscator")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    analyze_parser = subparsers.add_parser("analyze", help="Perform deep analysis and deobfuscation on a Python script")
    analyze_parser.add_argument("file", help="The target Python file to analyze. Supports .py scripts or raw text files containing obfuscated code.")
    analyze_parser.add_argument("--report", action="store_true", help="Generate detailed analysis reports in Markdown and JSON formats in the script's output directory.")
    analyze_parser.add_argument("--sandbox", action="store_true", help="Enable Safe Dynamic Analysis. Runs the script in a persistent, restricted environment to intercept dynamic 'exec', 'eval', and 'compile' calls without executing malicious payloads.")
    analyze_parser.add_argument("--extract-iocs", action="store_true", help="Perform static and dynamic extraction of Indicators of Compromise (URLs, IPs, Domains, Wallets) from all discovered code layers.")
    analyze_parser.add_argument("--verbose", action="store_true", help="Display detailed diagnostic logs, including plugin discovery, iteration steps, and interception events.")
    analyze_parser.add_argument("--output-dir", default="output", help="The base directory where analysis results will be stored. A script-specific subfolder will be created inside. (Default: 'output')")

    args = parser.parse_args()

    if args.command == "analyze":
        setup_logging(args.verbose)
        target_path = Path(args.file)
        if not target_path.exists():
            console.print(f"[red]Error:[/red] File {args.file} not found.")
            sys.exit(1)

        engine = DeobfuscationEngine(
            base_output_dir=Path(args.output_dir),
            use_sandbox=args.sandbox,
            extract_iocs=args.extract_iocs
        )

        try:
            console.print(f"[bold blue]Analyzing {target_path.name}...[/bold blue]")
            report = engine.analyze(target_path)
            
            # Reporting
            from pydeob.reporters import ConsoleReporter, JSONReporter, MarkdownReporter
            
            console_reporter = ConsoleReporter(console)
            console_reporter.report(report)
            
            if args.report:
                # Use the engine's output directory (which is script-specific)
                output_dir = engine.output_dir or Path(args.output_dir)
                json_path = output_dir / "report.json"
                md_path = output_dir / "report.md"
                
                json_reporter = JSONReporter()
                json_reporter.report(report, json_path)
                
                md_reporter = MarkdownReporter()
                md_reporter.report(report, md_path)
                
                console.print(f"\n[bold green]Reports saved to {output_dir}[/bold green]")
                
        except Exception as e:
            logging.exception("Analysis failed")
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
