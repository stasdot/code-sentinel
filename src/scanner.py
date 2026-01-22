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
from .prompts import get_prompt


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
        self.results = []
    
    def scan_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with scan results
        """
        # Read the file
        content = self.file_parser.read_file(file_path)
        
        if content is None:
            return {
                "file": str(file_path),
                "success": False,
                "error": "Failed to read file",
                "response": None
            }
        
        # Get file info
        file_info = self.file_parser.get_file_info(file_path)
        
        # Analyze with AI
        result = self.ai_client.analyze_code(
            code=content,
            filename=file_path.name,
            prompt_template=self.prompt_template
        )
        
        # Combine file info with analysis result
        result["file"] = str(file_path)
        result["file_info"] = file_info
        
        return result
    
    def scan_directory(self, path: str, verbose: bool = True) -> List[Dict[str, Any]]:
        """
        Scan all files in a directory.
        
        Args:
            path: Directory path to scan
            verbose: Show progress output
            
        Returns:
            List of scan results
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
        successful = sum(1 for r in self.results if r.get("success"))
        failed = len(self.results) - successful
        
        # Create summary table
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Files", str(len(self.results)))
        table.add_row("Successfully Analyzed", str(successful))
        table.add_row("Failed", str(failed))
        
        if successful > 0:
            avg_time = sum(r.get("elapsed_time", 0) for r in self.results if r.get("success")) / successful
            table.add_row("Avg Analysis Time", f"{avg_time:.2f}s")
        
        console.print()
        console.print(table)
        console.print()
        
        # Show a few sample results
        if successful > 0:
            console.print(Panel.fit(
                "[bold green]✓ Scan completed successfully![/bold green]\n"
                f"Analyzed {successful} files with AI model: {self.ai_client.model}",
                title="Results"
            ))


def scan(path: str, 
         model: str = "codellama",
         client_type: str = "ollama",
         prompt_type: str = "standard",
         verbose: bool = True) -> List[Dict[str, Any]]:
    """
    Main entry point for scanning.
    
    Args:
        path: Path to file or directory to scan
        model: AI model to use
        client_type: Type of AI client ('ollama', 'groq', etc.)
        prompt_type: Prompt template type
        verbose: Show progress and results
        
    Returns:
        List of scan results
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
    
    return scanner.scan_directory(path, verbose=verbose)


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
        console.print("\n[bold cyan]Sample Analysis Results:[/bold cyan]\n")
        for i, result in enumerate(results[:3], 1):  # Show first 3
            if result.get("success"):
                console.print(f"[bold]{i}. {result['file']}[/bold]")
                response_preview = result['response'][:300] + "..." if len(result['response']) > 300 else result['response']
                console.print(f"[dim]{response_preview}[/dim]\n")