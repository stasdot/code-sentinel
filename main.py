#!/usr/bin/env python3
"""
CODE SENTINEL - CLI Entry Point
Simple command-line interface for running scans.
"""

import sys
import argparse
from pathlib import Path
from rich.console import Console

from src.scanner import scan

console = Console()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CODE SENTINEL - AI-Powered Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan ./my-project
  python main.py scan ./app.py --model codellama
  python main.py scan . --prompt detailed
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for vulnerabilities")
    scan_parser.add_argument(
        "path",
        type=str,
        help="Path to file or directory to scan"
    )
    scan_parser.add_argument(
        "--model",
        type=str,
        default="codellama",
        help="AI model to use (default: codellama)"
    )
    scan_parser.add_argument(
        "--client",
        type=str,
        default="ollama",
        choices=["ollama"],
        help="AI client type (default: ollama)"
    )
    scan_parser.add_argument(
        "--prompt",
        type=str,
        default="standard",
        choices=["standard", "detailed", "quick"],
        help="Prompt template type (default: standard)"
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal output"
    )
    
    args = parser.parse_args()
    
    # Show help if no command
    if not args.command:
        parser.print_help()
        return
    
    # Handle scan command
    if args.command == "scan":
        path = Path(args.path)
        
        if not path.exists():
            console.print(f"[red]✗ Path does not exist: {path}[/red]")
            sys.exit(1)
        
        results = scan(
            path=str(path),
            model=args.model,
            client_type=args.client,
            prompt_type=args.prompt,
            verbose=not args.quiet
        )
        
        if not results:
            sys.exit(1)
        
        # Exit with error if any scan failed or critical/high vulnerabilities found
        failed = sum(1 for r in results if not r.success)
        if failed > 0:
            sys.exit(1)
        
        # Check for critical/high severity vulnerabilities
        from src.models import Severity
        critical_high = sum(
            1 for r in results 
            for v in r.vulnerabilities 
            if v.severity in [Severity.CRITICAL, Severity.HIGH]
        )
        if critical_high > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()