"""
Data models for vulnerability findings and scan results.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import json


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    def __lt__(self, other):
        """Compare severity levels for sorting."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        return order[self] < order[other]


@dataclass
class Vulnerability:
    """Represents a single security vulnerability finding."""
    
    type: str  # e.g., "SQL Injection", "XSS"
    severity: Severity
    line: Optional[int]
    code_snippet: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None  # e.g., "CWE-89"
    confidence: float = 1.0  # 0.0 to 1.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "severity": self.severity.value,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Vulnerability':
        """Create from dictionary."""
        return cls(
            type=data.get("type", "Unknown"),
            severity=Severity(data.get("severity", "medium")),
            line=data.get("line"),
            code_snippet=data.get("code_snippet", ""),
            description=data.get("description", ""),
            recommendation=data.get("recommendation", ""),
            cwe_id=data.get("cwe_id"),
            confidence=data.get("confidence", 1.0)
        )


@dataclass
class ScanResult:
    """Complete scan result for a file."""
    
    file_path: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: float = 0.0
    model_used: str = ""
    success: bool = True
    error: Optional[str] = None
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the result."""
        self.vulnerabilities.append(vuln)
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities by severity level."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_statistics(self) -> dict:
        """Get statistics about vulnerabilities found."""
        stats = {
            "total": len(self.vulnerabilities),
            "by_severity": {},
            "by_type": {}
        }
        
        # Count by severity
        for severity in Severity:
            count = len(self.get_by_severity(severity))
            if count > 0:
                stats["by_severity"][severity.value] = count
        
        # Count by type
        for vuln in self.vulnerabilities:
            vuln_type = vuln.type
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1
        
        return stats
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "file_path": self.file_path,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_time": self.scan_time,
            "model_used": self.model_used,
            "success": self.success,
            "error": self.error,
            "statistics": self.get_statistics()
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


# JSON Schema for AI response validation
VULNERABILITY_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "description": "Type of vulnerability (e.g., 'SQL Injection', 'XSS')"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    },
                    "line": {
                        "type": ["integer", "null"],
                        "description": "Line number where vulnerability occurs"
                    },
                    "code_snippet": {
                        "type": "string",
                        "description": "Relevant code snippet"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability"
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "How to fix the vulnerability"
                    },
                    "cwe_id": {
                        "type": ["string", "null"],
                        "description": "CWE identifier (e.g., 'CWE-89')"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level (0.0 to 1.0)"
                    }
                },
                "required": ["type", "severity", "description", "recommendation"]
            }
        }
    },
    "required": ["vulnerabilities"]
}


def get_schema_description() -> str:
    """Get a human-readable description of the expected JSON schema."""
    return """
{
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "critical",
      "line": 45,
      "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
      "description": "User input is directly concatenated into SQL query without sanitization",
      "recommendation": "Use parameterized queries or an ORM to prevent SQL injection",
      "cwe_id": "CWE-89",
      "confidence": 0.95
    }
  ]
}
"""