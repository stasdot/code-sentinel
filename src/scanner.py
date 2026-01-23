"""
Main scanning orchestrator for CODE SENTINEL.
Coordinates file discovery and AI-powered security analysis.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table

from .parser import FileParser
from .ai_client import create_client, AIClient
from .prompts import get_prompt, format_prompt
from .response_parser import ResponseParser
from .models import ScanResult, Severity


console = Console()


class CodeScanner:
    """Main scanner that coordinates file parsing and AI analysis."""
    
    def __init__(self, 
                 ai_client: AIClient,
                 file_parser: Optional[FileParser] = None,
                 prompt_type: str = "standard"):
        """
        Initialize the code scanner.
        
        Args:
            ai_client: AI client instance for code analysis
            file_parser: File parser instance (creates default if None)
            prompt_type: Type of prompt to use ('standard', 'detailed', 'quick')
        """
        self.ai_client = ai_client
        self.file_parser = file_parser or FileParser()
        self.prompt_template = get_prompt(prompt_type)
        self.parser = ResponseParser()
        self.results: List[ScanResult] = []
    
    def scan_file(self, file_path: Path) -> ScanResult:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            file_path: Path to the file
            
        Returns:
            ScanResult object with findings
        """
        # Read the file
        content = self.file_parser.read_file(file_path)
        
        if content is None:
            return ScanResult(
                file_path=str(file_path),
                success=False,
                error="Failed to read file",
                model_used=self.ai_client.model
            )
        
        # Format the prompt with actual values
        prompt = format_prompt(
            self.prompt_template,
            filename=file_path.name,
            code=content
        )
        
        # Analyze with AI
        ai_result = self.ai_client.analyze_code(
            code=content,
            filename=file_path.name,
            prompt_template=prompt
        )
        
        if not ai_result["success"]:
            return ScanResult(
                file_path=str(file_path),
                success=False,
                error=ai_result.get("error", "AI analysis failed"),
                model_used=self.ai_client.model,
                scan_time=ai_result.get("elapsed_time", 0.0)
            )
        
        # Parse the AI response into structured data
        result = self.parser.parse_response(
            text=ai_result["response"],
            file_path=str(file_path),
            model_used=self.ai_client.model,
            scan_time=ai_result["elapsed_time"]
        )
        
        # If JSON parsing failed, try legacy parsing
        if not result.success:
            result = self.parser.parse_legacy_response(
                text=ai_result["response"],
                file_path=str(file_path),
                model_used=self.ai_client.model,
                scan_time=ai_result["elapsed_time"]
            )
        
        return result
    
    def scan_directory(self, path: str, verbose: bool = True) -> List[ScanResult]:
        """
        Scan all files in a directory.
        
        Args:
            path: Directory path to scan
            verbose: Show progress output
            
        Returns:
            List of ScanResult objects
        """
        self.results = []
        
        # Discover files
        if verbose:
            console.print(f"\n[cyan]🔍 Discovering files in: {path}[/cyan]")
        
        files = self.file_parser.discover_files(path)
        
        if not files:
            console.print("[yellow]⚠ No files found to scan[/yellow]")
            return []
        
        if verbose:
            console.print(f"[green]✓ Found {len(files)} files to scan[/green]\n")
        
        # Scan files with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Scanning files...", 
                total=len(files)
            )
            
            for file_path in files:
                if verbose:
                    progress.update(
                        task, 
                        description=f"[cyan]Scanning: {file_path.name}"
                    )
                
                result = self.scan_file(file_path)
                self.results.append(result)
                
                progress.advance(task)
        
        if verbose:
            self._display_summary()
        
        return self.results
    
    def _display_summary(self):
        """Display a summary of scan results."""
        successful = sum(1 for r in self.results if r.success)
        failed = len(self.results) - successful
        
        # Count total vulnerabilities
        total_vulns = sum(len(r.vulnerabilities) for r in self.results if r.success)
        
        # Count by severity
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        for result in self.results:
            if result.success:
                for vuln in result.vulnerabilities:
                    severity_counts[vuln.severity] += 1
        
        # Create summary table
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Files", str(len(self.results)))
        table.add_row("Successfully Analyzed", str(successful))
        table.add_row("Failed", str(failed))
        table.add_row("Total Vulnerabilities", str(total_vulns))
        
        # Add severity breakdown
        if total_vulns > 0:
            table.add_row("", "")  # Blank row
            table.add_row("By Severity:", "")
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = severity_counts[severity]
                if count > 0:
                    color = self._get_severity_color(severity)
                    table.add_row(f"  {severity.value.title()}", f"[{color}]{count}[/{color}]")
        
        if successful > 0:
            avg_time = sum(r.scan_time for r in self.results if r.success) / successful
            table.add_row("", "")  # Blank row
            table.add_row("Avg Analysis Time", f"{avg_time:.2f}s")
        
        console.print()
        console.print(table)
        console.print()
        
        # Show summary message
        if total_vulns > 0:
            critical_high = severity_counts[Severity.CRITICAL] + severity_counts[Severity.HIGH]
            if critical_high > 0:
                console.print(Panel.fit(
                    f"[bold red]⚠ Found {total_vulns} vulnerabilities ({critical_high} critical/high)[/bold red]\n"
                    f"Review findings carefully and address high-severity issues first.",
                    title="⚠️  Security Issues Found"
                ))
            else:
                console.print(Panel.fit(
                    f"[bold yellow]Found {total_vulns} vulnerabilities (all medium/low/info)[/bold yellow]\n"
                    f"No critical or high severity issues detected.",
                    title="Security Findings"
                ))
        else:
            console.print(Panel.fit(
                f"[bold green]✓ No vulnerabilities detected![/bold green]\n"
                f"Analyzed {successful} files with AI model: {self.ai_client.model}",
                title="✓ Clean Scan"
            ))
    
    def _get_severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        colors = {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan"
        }
        return colors.get(severity, "white")


def scan(path: str, 
         model: str = "codellama",
         client_type: str = "ollama",
         prompt_type: str = "standard",
         verbose: bool = True) -> List[ScanResult]:
    """
    Main entry point for scanning.
    
    Args:
        path: Path to file or directory to scan
        model: AI model to use
        client_type: Type of AI client ('ollama', 'groq', etc.)
        prompt_type: Prompt template type
        verbose: Show progress and results
        
    Returns:
        List of ScanResult objects
    """
    # Create AI client
    if verbose:
        console.print(Panel.fit(
            f"[bold cyan]CODE SENTINEL[/bold cyan]\n"
            f"AI-Powered Security Scanner\n\n"
            f"Model: {model}\n"
            f"Client: {client_type}",
            title="🛡️  Starting Scan"
        ))
    
    ai_client = create_client(client_type, model=model)
    
    # Test connection
    if verbose:
        console.print("\n[cyan]Testing AI connection...[/cyan]")
    
    if not ai_client.test_connection():
        console.print("[red]✗ Failed to connect to AI service[/red]")
        return []
    
    console.print("[green]✓ AI connection successful[/green]")
    
    # Create scanner and run
    scanner = CodeScanner(
        ai_client=ai_client,
        prompt_type=prompt_type
    )
    
    results = scanner.scan_directory(path, verbose=verbose)
    
    # Show detailed vulnerability information
    if verbose and results:
        _display_detailed_vulnerabilities(results)
    
    return results


def _display_detailed_vulnerabilities(results: List[ScanResult]):
    """Display detailed vulnerability information."""
    console.print("\n[bold cyan]═══ Vulnerability Details ═══[/bold cyan]\n")
    shown = 0
    
    for result in results:
        if result.success and result.vulnerabilities:
            console.print(f"[bold underline]📄 {result.file_path}[/bold underline]")
            console.print(f"[dim]Scanned in {result.scan_time:.2f}s with {result.model_used}[/dim]\n")
            
            for i, vuln in enumerate(result.vulnerabilities, 1):
                # Color based on severity
                if vuln.severity == Severity.CRITICAL:
                    color = "bright_red"
                    icon = "🔴"
                elif vuln.severity == Severity.HIGH:
                    color = "red"
                    icon = "🟠"
                elif vuln.severity == Severity.MEDIUM:
                    color = "yellow"
                    icon = "🟡"
                elif vuln.severity == Severity.LOW:
                    color = "blue"
                    icon = "🔵"
                else:
                    color = "cyan"
                    icon = "ℹ️"
                
                console.print(f"[bold]{i}. [{color}]{icon} {vuln.type}[/{color}][/bold]")
                console.print(f"   [dim]Severity:[/dim] [{color}]{vuln.severity.value.upper()}[/{color}]")
                if vuln.line:
                    console.print(f"   [dim]Line:[/dim] {vuln.line}")
                if vuln.cwe_id:
                    console.print(f"   [dim]CWE:[/dim] {vuln.cwe_id}")
                console.print(f"   [dim]Confidence:[/dim] {vuln.confidence:.0%}")
                console.print(f"\n   [bold]Description:[/bold]")
                console.print(f"   {vuln.description}")
                if vuln.code_snippet:
                    console.print(f"\n   [bold]Code Snippet:[/bold]")
                    console.print(f"   [dim]{vuln.code_snippet}[/dim]")
                console.print(f"\n   [bold green]✓ Recommendation:[/bold green]")
                console.print(f"   {vuln.recommendation}\n")
            
            shown += 1
            if shown >= 5:  # Limit to 5 files to avoid too much output
                remaining = len([r for r in results if r.success and r.vulnerabilities]) - shown
                if remaining > 0:
                    console.print(f"[dim]... and {remaining} more files with vulnerabilities[/dim]\n")
                break
    
    if shown == 0:
        console.print("[dim]No vulnerabilities found in scanned files.[/dim]\n")


if __name__ == "__main__":
    import sys
    
    # Simple CLI for testing
    if len(sys.argv) < 2:
        console.print("[yellow]Usage: python -m src.scanner <path>[/yellow]")
        console.print("[yellow]Example: python -m src.scanner ./my-project[/yellow]")
        sys.exit(1)
    
    path = sys.argv[1]
    results = scan(path)
    
    # Show a sample of results
    if results:
        console.print("\n[bold cyan]═══ Vulnerability Details ═══[/bold cyan]\n")
        shown = 0
        for result in results:
            if result.success and result.vulnerabilities:
                console.print(f"[bold underline]📄 {result.file_path}[/bold underline]")
                console.print(f"[dim]Scanned in {result.scan_time:.2f}s with {result.model_used}[/dim]\n")
                
                for i, vuln in enumerate(result.vulnerabilities, 1):
                    # Color based on severity
                    if vuln.severity == Severity.CRITICAL:
                        color = "bright_red"
                        icon = "🔴"
                    elif vuln.severity == Severity.HIGH:
                        color = "red"
                        icon = "🟠"
                    elif vuln.severity == Severity.MEDIUM:
                        color = "yellow"
                        icon = "🟡"
                    elif vuln.severity == Severity.LOW:
                        color = "blue"
                        icon = "🔵"
                    else:
                        color = "cyan"
                        icon = "ℹ️"
                    
                    console.print(f"[bold]{i}. [{color}]{icon} {vuln.type}[/{color}][/bold]")
                    console.print(f"   [dim]Severity:[/dim] [{color}]{vuln.severity.value.upper()}[/{color}]")
                    if vuln.line:
                        console.print(f"   [dim]Line:[/dim] {vuln.line}")
                    if vuln.cwe_id:
                        console.print(f"   [dim]CWE:[/dim] {vuln.cwe_id}")
                    console.print(f"   [dim]Confidence:[/dim] {vuln.confidence:.0%}")
                    console.print(f"\n   [bold]Description:[/bold]")
                    console.print(f"   {vuln.description}")
                    console.print(f"\n   [bold]Code Snippet:[/bold]")
                    console.print(f"   [dim]{vuln.code_snippet}[/dim]")
                    console.print(f"\n   [bold green]✓ Recommendation:[/bold green]")
                    console.print(f"   {vuln.recommendation}\n")
                
                shown += 1
                if shown >= 5:  # Limit to 5 files to avoid too much output
                    remaining = len([r for r in results if r.success and r.vulnerabilities]) - shown
                    if remaining > 0:
                        console.print(f"[dim]... and {remaining} more files with vulnerabilities[/dim]\n")
                    break
        
        if shown == 0:
            console.print("[dim]No vulnerabilities found in scanned files.[/dim]\n")