"""
Prompt templates for AI-powered security analysis with structured JSON output.
"""

from .models import get_schema_description


STRUCTURED_SECURITY_PROMPT = """You are a security expert. Analyze this code for vulnerabilities.

File: {filename}
Code:
```
{code}
```

RESPOND WITH ONLY JSON. NO OTHER TEXT. START WITH {{ and END WITH }}.

Use this exact format:
{schema}

If no vulnerabilities found, return:
{{"vulnerabilities": []}}

JSON ONLY. NO EXPLANATIONS."""


DETAILED_STRUCTURED_PROMPT = """Security analysis for: {filename}

Code:
```
{code}
```

RETURN ONLY JSON. Format:
{schema}

Analyze: input validation, injections, auth issues, crypto, data exposure.

JSON ONLY. START WITH {{ END WITH }}"""


QUICK_STRUCTURED_PROMPT = """Security scan for: {filename}

Code:
```
{code}
```

Find common vulnerabilities. Respond with ONLY this JSON format:
{schema}

Be concise but accurate. JSON only, no other text."""


def get_prompt(prompt_type: str = "standard") -> str:
    """
    Get a prompt template by type.
    
    Args:
        prompt_type: Type of prompt ('standard', 'detailed', 'quick')
        
    Returns:
        Prompt template string (unformatted, with placeholders)
    """
    prompts = {
        "standard": STRUCTURED_SECURITY_PROMPT,
        "detailed": DETAILED_STRUCTURED_PROMPT,
        "quick": QUICK_STRUCTURED_PROMPT,
    }
    
    return prompts.get(prompt_type, STRUCTURED_SECURITY_PROMPT)


def format_prompt(template: str, filename: str, code: str) -> str:
    """
    Format a prompt template with actual values.
    
    Args:
        template: Prompt template string
        filename: Name of file being analyzed
        code: Source code content
        
    Returns:
        Formatted prompt ready to send to AI
    """
    schema = get_schema_description()
    return template.format(
        filename=filename,
        code=code,
        schema=schema
    )