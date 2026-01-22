"""
Prompt templates for AI-powered security analysis.
"""

SECURITY_ANALYSIS_PROMPT = """You are a security expert analyzing code for vulnerabilities.

Analyze the following code from file "{filename}" and identify any security vulnerabilities.

Code:
```
{code}
```

For each vulnerability found, provide:
1. Type of vulnerability (e.g., SQL Injection, XSS, Path Traversal)
2. Severity (critical, high, medium, low)
3. Line number where the issue occurs
4. Brief description of the issue
5. Recommendation for fixing it
6. CWE ID if applicable

If no vulnerabilities are found, state that the code appears secure.

Be specific and actionable in your recommendations."""


DETAILED_ANALYSIS_PROMPT = """You are an expert security code reviewer. Analyze this code for security vulnerabilities.

File: {filename}

Code:
```
{code}
```

Provide a detailed security analysis covering:

1. **Input Validation**: Are user inputs properly validated and sanitized?
2. **Authentication & Authorization**: Are there any access control issues?
3. **Injection Flaws**: SQL injection, command injection, code injection, etc.
4. **Cryptography**: Are cryptographic functions used correctly?
5. **Error Handling**: Does error handling leak sensitive information?
6. **Data Exposure**: Is sensitive data properly protected?
7. **Dependencies**: Are there known vulnerable dependencies?

For each issue found, specify:
- Vulnerability type
- Severity level (critical/high/medium/low)
- Exact line number
- Detailed explanation
- Specific fix recommendation
- Relevant CWE/OWASP reference

Format your response clearly with sections for each vulnerability found."""


QUICK_SCAN_PROMPT = """Quickly scan this code for common security issues:

File: {filename}
```
{code}
```

List any security vulnerabilities found with:
- Type
- Severity
- Line number
- Brief fix suggestion

Be concise but accurate."""


def get_prompt(prompt_type: str = "standard") -> str:
    """
    Get a prompt template by type.
    
    Args:
        prompt_type: Type of prompt ('standard', 'detailed', 'quick')
        
    Returns:
        Prompt template string
    """
    prompts = {
        "standard": SECURITY_ANALYSIS_PROMPT,
        "detailed": DETAILED_ANALYSIS_PROMPT,
        "quick": QUICK_SCAN_PROMPT,
    }
    
    return prompts.get(prompt_type, SECURITY_ANALYSIS_PROMPT)