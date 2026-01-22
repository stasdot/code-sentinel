"""
CODE SENTINEL - AI-Powered Code Security Scanner
"""

from .scanner import CodeScanner, scan
from .parser import FileParser
from .ai_client import AIClient, OllamaClient, create_client
from .prompts import get_prompt

__version__ = "0.1.0"
__all__ = [
    "CodeScanner",
    "scan",
    "FileParser",
    "AIClient",
    "OllamaClient",
    "create_client",
    "get_prompt",
]