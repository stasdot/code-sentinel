"""
Parser for AI responses to extract structured vulnerability data.
"""

import json
import re
from typing import List, Optional, Dict, Any
from .models import Vulnerability, ScanResult, Severity


class ResponseParser:
    """Parses AI responses into structured vulnerability data."""
    
    @staticmethod
    def extract_json(text: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON from AI response, handling markdown code blocks.
        
        Args:
            text: Raw AI response text
            
        Returns:
            Parsed JSON dict or None if parsing failed
        """
        # Try to find JSON in markdown code block
        json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
        match = re.search(json_pattern, text, re.DOTALL)
        
        if match:
            json_str = match.group(1)
        else:
            # Try to find raw JSON object
            json_pattern = r'\{.*"vulnerabilities".*\}'
            match = re.search(json_pattern, text, re.DOTALL)
            if match:
                json_str = match.group(0)
            else:
                # Last resort: assume entire text is JSON
                json_str = text.strip()
        
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            print(f"Text was: {text[:200]}...")
            return None
    
    @staticmethod
    def parse_vulnerabilities(data: Dict[str, Any]) -> List[Vulnerability]:
        """
        Parse vulnerabilities from JSON data.
        
        Args:
            data: Parsed JSON dictionary
            
        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        
        vulns_data = data.get("vulnerabilities", [])
        
        for vuln_data in vulns_data:
            try:
                vuln = Vulnerability.from_dict(vuln_data)
                vulnerabilities.append(vuln)
            except Exception as e:
                print(f"Warning: Failed to parse vulnerability: {e}")
                print(f"Data: {vuln_data}")
                continue
        
        return vulnerabilities
    
    @staticmethod
    def parse_response(text: str, file_path: str, model_used: str, 
                      scan_time: float) -> ScanResult:
        """
        Parse complete AI response into ScanResult.
        
        Args:
            text: Raw AI response
            file_path: Path to scanned file
            model_used: AI model identifier
            scan_time: Time taken for scan
            
        Returns:
            ScanResult object
        """
        result = ScanResult(
            file_path=file_path,
            model_used=model_used,
            scan_time=scan_time
        )
        
        # Extract and parse JSON
        data = ResponseParser.extract_json(text)
        
        if data is None:
            result.success = False
            result.error = "Failed to extract JSON from AI response"
            return result
        
        # Parse vulnerabilities
        try:
            vulnerabilities = ResponseParser.parse_vulnerabilities(data)
            result.vulnerabilities = vulnerabilities
            result.success = True
        except Exception as e:
            result.success = False
            result.error = f"Failed to parse vulnerabilities: {e}"
        
        return result
    
    @staticmethod
    def parse_legacy_response(text: str, file_path: str, model_used: str,
                             scan_time: float) -> ScanResult:
        """
        Parse non-JSON AI response using pattern matching.
        Fallback for when AI doesn't return proper JSON.
        
        Args:
            text: Raw AI response
            file_path: Path to scanned file
            model_used: AI model identifier
            scan_time: Time taken for scan
            
        Returns:
            ScanResult object
        """
        result = ScanResult(
            file_path=file_path,
            model_used=model_used,
            scan_time=scan_time
        )
        
        # Check if response indicates no vulnerabilities
        no_vuln_patterns = [
            r'no vulnerabilities',
            r'appears secure',
            r'no security issues',
            r'no issues found',
            r'code is secure'
        ]
        
        text_lower = text.lower()
        if any(re.search(pattern, text_lower) for pattern in no_vuln_patterns):
            result.success = True
            return result
        
        # Try to extract basic vulnerability info using patterns
        # This is a simple fallback - won't be as accurate as JSON
        severity_pattern = r'(critical|high|medium|low)'
        matches = re.finditer(severity_pattern, text_lower)
        
        # Create a generic vulnerability entry
        if list(re.finditer(severity_pattern, text_lower)):
            vuln = Vulnerability(
                type="Security Issue",
                severity=Severity.MEDIUM,
                line=None,
                code_snippet="",
                description=text[:500],  # First 500 chars as description
                recommendation="Review AI analysis for details",
                confidence=0.5
            )
            result.add_vulnerability(vuln)
        
        result.success = True
        return result


if __name__ == "__main__":
    # Test the parser
    sample_response = """
    Here's the analysis:
    
    ```json
    {
      "vulnerabilities": [
        {
          "type": "SQL Injection",
          "severity": "critical",
          "line": 10,
          "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
          "description": "Direct string concatenation in SQL query",
          "recommendation": "Use parameterized queries",
          "cwe_id": "CWE-89",
          "confidence": 0.95
        }
      ]
    }
    ```
    """
    
    parser = ResponseParser()
    result = parser.parse_response(sample_response, "test.py", "codellama", 1.5)
    
    print(f"Success: {result.success}")
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    if result.vulnerabilities:
        print(f"First vuln: {result.vulnerabilities[0].type}")
        print(result.to_json())