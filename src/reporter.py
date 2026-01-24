"""
Report generation for CODE SENTINEL scan results.
Supports multiple output formats: HTML, JSON, Markdown, Terminal.
"""

import json
from pathlib import Path
from typing import List
from datetime import datetime
from .models import ScanResult, Severity


class Reporter:
    """Generate reports in various formats."""
    
    @staticmethod
    def generate_html(results: List[ScanResult], output_path: str = "report.html"):
        """
        Generate detailed HTML report.
        
        Args:
            results: List of scan results
            output_path: Path to save HTML file
        """
        # Calculate statistics
        total_files = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total_files - successful
        total_vulns = sum(len(r.vulnerabilities) for r in results if r.success)
        
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        for result in results:
            if result.success:
                for vuln in result.vulnerabilities:
                    severity_counts[vuln.severity] += 1
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CODE SENTINEL - Security Scan Report</title>
    <style>
        :root {{
            --primary-color: #2563eb;
            --danger-color: #dc2626;
            --warning-color: #f59e0b;
            --success-color: #10b981;
            --info-color: #3b82f6;
            --bg-color: #f9fafb;
            --card-bg: #ffffff;
            --text-color: #1f2937;
            --border-color: #e5e7eb;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .summary-card {{
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            border-left: 4px solid var(--primary-color);
        }}
        
        .summary-card.critical {{
            border-left-color: #dc2626;
        }}
        
        .summary-card.high {{
            border-left-color: #ea580c;
        }}
        
        .summary-card.medium {{
            border-left-color: #f59e0b;
        }}
        
        .summary-card.low {{
            border-left-color: #3b82f6;
        }}
        
        .summary-card h3 {{
            font-size: 0.875rem;
            color: #6b7280;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }}
        
        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--text-color);
        }}
        
        .section {{
            background: var(--card-bg);
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}
        
        .section h2 {{
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: var(--text-color);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 0.5rem;
        }}
        
        .vulnerability {{
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: box-shadow 0.2s;
        }}
        
        .vulnerability:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }}
        
        .vulnerability-title {{
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge.critical {{
            background: #fee2e2;
            color: #dc2626;
        }}
        
        .badge.high {{
            background: #ffedd5;
            color: #ea580c;
        }}
        
        .badge.medium {{
            background: #fef3c7;
            color: #d97706;
        }}
        
        .badge.low {{
            background: #dbeafe;
            color: #2563eb;
        }}
        
        .badge.info {{
            background: #e0e7ff;
            color: #4f46e5;
        }}
        
        .file-path {{
            font-family: 'Courier New', monospace;
            background: #f3f4f6;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }}
        
        .vuln-details {{
            display: grid;
            gap: 1rem;
        }}
        
        .detail-row {{
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 1rem;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: #6b7280;
        }}
        
        .detail-value {{
            color: var(--text-color);
        }}
        
        .code-snippet {{
            background: #1f2937;
            color: #f9fafb;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            margin: 1rem 0;
        }}
        
        .recommendation {{
            background: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
        }}
        
        .recommendation-title {{
            font-weight: 600;
            color: #059669;
            margin-bottom: 0.5rem;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #6b7280;
            font-size: 0.875rem;
        }}
        
        .no-vulns {{
            text-align: center;
            padding: 3rem;
            color: #6b7280;
        }}
        
        .no-vulns-icon {{
            font-size: 4rem;
            margin-bottom: 1rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CODE SENTINEL</h1>
            <div class="subtitle">Security Scan Report - {datetime.now().strftime("%B %d, %Y at %H:%M")}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Files</h3>
                <div class="value">{total_files}</div>
            </div>
            <div class="summary-card">
                <h3>Analyzed</h3>
                <div class="value">{successful}</div>
            </div>
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{total_vulns}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="value">{severity_counts[Severity.CRITICAL]}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="value">{severity_counts[Severity.HIGH]}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="value">{severity_counts[Severity.MEDIUM]}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="value">{severity_counts[Severity.LOW]}</div>
            </div>
        </div>
"""
        
        # Add vulnerabilities section
        if total_vulns > 0:
            html += """
        <div class="section">
            <h2>Vulnerability Details</h2>
"""
            for result in results:
                if result.success and result.vulnerabilities:
                    html += f"""
            <div class="file-path">📄 {result.file_path}</div>
"""
                    for vuln in result.vulnerabilities:
                        html += f"""
            <div class="vulnerability">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">
                        {Reporter._get_emoji(vuln.severity)} {vuln.type}
                    </div>
                    <span class="badge {vuln.severity.value}">{vuln.severity.value}</span>
                </div>
                
                <div class="vuln-details">
                    <div class="detail-row">
                        <div class="detail-label">Line:</div>
                        <div class="detail-value">{vuln.line or 'N/A'}</div>
                    </div>
"""
                        if vuln.cwe_id:
                            html += f"""
                    <div class="detail-row">
                        <div class="detail-label">CWE ID:</div>
                        <div class="detail-value">{vuln.cwe_id}</div>
                    </div>
"""
                        html += f"""
                    <div class="detail-row">
                        <div class="detail-label">Confidence:</div>
                        <div class="detail-value">{vuln.confidence:.0%}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Description:</div>
                        <div class="detail-value">{vuln.description}</div>
                    </div>
"""
                        if vuln.code_snippet:
                            html += f"""
                    <div class="code-snippet">{Reporter._format_code_with_pointer(vuln.code_snippet, vuln.line)}</div>
"""
                        html += f"""
                    <div class="recommendation">
                        <div class="recommendation-title">✓ Recommendation:</div>
                        <div>{vuln.recommendation}</div>
                    </div>
                </div>
            </div>
"""
            html += """
        </div>
"""
        else:
            html += """
        <div class="section">
            <div class="no-vulns">
                <div class="no-vulns-icon">✅</div>
                <h3>No Vulnerabilities Found</h3>
                <p>All scanned files appear to be secure!</p>
            </div>
        </div>
"""
        
        # Footer
        html += f"""
        <div class="footer">
            Generated by CODE SENTINEL | Report contains {total_vulns} findings across {successful} files
        </div>
    </div>
</body>
</html>
"""
        
        # Write to file
        Path(output_path).write_text(html, encoding='utf-8')
        return output_path
    
    @staticmethod
    def generate_json(results: List[ScanResult], output_path: str = "report.json"):
        """Generate JSON report."""
        data = {
            "scan_date": datetime.now().isoformat(),
            "total_files": len(results),
            "results": [r.to_dict() for r in results]
        }
        
        Path(output_path).write_text(
            json.dumps(data, indent=2),
            encoding='utf-8'
        )
        return output_path
    
    @staticmethod
    def _get_emoji(severity: Severity) -> str:
        """Get emoji for severity level."""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "ℹ️"
        }
        return emojis.get(severity, "")
    
    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
    
    @staticmethod
    def _format_code_with_pointer(code_snippet: str, line_number: Optional[int]) -> str:
        """Format code snippet with line numbers and pointer arrow."""
        if not line_number:
            return Reporter._escape_html(code_snippet)
        
        lines = code_snippet.split('\n')
        formatted_lines = []
        
        for i, line in enumerate(lines, start=1):
            escaped_line = Reporter._escape_html(line)
            # Add pointer arrow to the vulnerable line
            if len(lines) == 1:
                # Single line snippet - add arrow before it
                formatted_lines.append(f'<span style="color: #ef4444;">→ </span>{escaped_line}')
            else:
                # Multi-line snippet - show line numbers
                line_num = f'{line_number + i - 1:3d}'
                if i == 1:  # First line is typically the vulnerable one
                    formatted_lines.append(f'<span style="color: #ef4444;">{line_num} → </span>{escaped_line}')
                else:
                    formatted_lines.append(f'<span style="color: #6b7280;">{line_num}   </span>{escaped_line}')
        
        return '\n'.join(formatted_lines)