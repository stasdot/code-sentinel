"""
Context management for CODE SENTINEL.
Handles code chunking, token counting, and context building for AI analysis.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CodeChunk:
    """Represents a chunk of code for analysis."""
    content: str
    start_line: int
    end_line: int
    file_path: str
    chunk_index: int
    total_chunks: int
    imports: List[str] = None
    
    def __post_init__(self):
        if self.imports is None:
            self.imports = []


class ContextManager:
    """Manages code context for AI analysis."""
    
    # Token limits for different models
    TOKEN_LIMITS = {
        "codellama": 4096,
        "llama-3.3-70b-versatile": 8000,
        "llama-3.1-70b-versatile": 8000,
        "mixtral-8x7b-32768": 32000,
        "mistral": 8000,
        "qwen2.5-coder": 32000,
    }
    
    # Rough estimate: 1 token ≈ 4 characters
    CHARS_PER_TOKEN = 4
    
    # Max tokens to reserve for prompt and response
    PROMPT_OVERHEAD = 1000
    RESPONSE_TOKENS = 2000
    
    def __init__(self, model_name: str = "codellama", max_chunk_lines: int = 500):
        """
        Initialize context manager.
        
        Args:
            model_name: AI model name for token limit
            max_chunk_lines: Maximum lines per chunk
        """
        self.model_name = model_name
        self.max_chunk_lines = max_chunk_lines
        self.token_limit = self._get_token_limit(model_name)
        self.max_code_tokens = self.token_limit - self.PROMPT_OVERHEAD - self.RESPONSE_TOKENS
    
    def _get_token_limit(self, model_name: str) -> int:
        """Get token limit for model."""
        # Check if model name contains known models
        for key, limit in self.TOKEN_LIMITS.items():
            if key in model_name.lower():
                return limit
        # Default to safe limit
        return 4096
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        
        Args:
            text: Text to estimate
            
        Returns:
            Estimated token count
        """
        return len(text) // self.CHARS_PER_TOKEN
    
    def needs_chunking(self, code: str) -> bool:
        """
        Check if code needs to be chunked.
        
        Args:
            code: Source code to check
            
        Returns:
            True if code should be chunked
        """
        estimated_tokens = self.estimate_tokens(code)
        line_count = code.count('\n') + 1
        
        return estimated_tokens > self.max_code_tokens or line_count > self.max_chunk_lines
    
    def extract_imports(self, code: str, language: str = "python") -> List[str]:
        """
        Extract import statements from code.
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            List of import statements
        """
        imports = []
        
        if language in ["python", ".py"]:
            # Python imports
            import_pattern = r'^(import\s+[\w.]+|from\s+[\w.]+\s+import\s+.+)$'
            for line in code.split('\n'):
                if re.match(import_pattern, line.strip()):
                    imports.append(line.strip())
        
        elif language in ["javascript", "typescript", ".js", ".ts", ".jsx", ".tsx"]:
            # JavaScript/TypeScript imports
            import_pattern = r'^(import\s+.+from\s+[\'"].+[\'"]|const\s+.+=\s+require\([\'"].+[\'"]\))$'
            for line in code.split('\n'):
                if re.match(import_pattern, line.strip()):
                    imports.append(line.strip())
        
        elif language in ["java", ".java"]:
            # Java imports
            import_pattern = r'^import\s+[\w.]+;$'
            for line in code.split('\n'):
                if re.match(import_pattern, line.strip()):
                    imports.append(line.strip())
        
        elif language in ["go", ".go"]:
            # Go imports
            in_import_block = False
            for line in code.split('\n'):
                stripped = line.strip()
                if stripped.startswith('import ('):
                    in_import_block = True
                    imports.append(stripped)
                elif in_import_block:
                    if stripped == ')':
                        in_import_block = False
                    imports.append(stripped)
                elif stripped.startswith('import '):
                    imports.append(stripped)
        
        return imports
    
    def chunk_code(self, code: str, file_path: str, language: str = "python") -> List[CodeChunk]:
        """
        Split code into manageable chunks.
        
        Args:
            code: Source code to chunk
            file_path: Path to the file
            language: Programming language
            
        Returns:
            List of CodeChunk objects
        """
        if not self.needs_chunking(code):
            # No chunking needed
            imports = self.extract_imports(code, language)
            return [CodeChunk(
                content=code,
                start_line=1,
                end_line=code.count('\n') + 1,
                file_path=file_path,
                chunk_index=0,
                total_chunks=1,
                imports=imports
            )]
        
        # Extract imports once
        imports = self.extract_imports(code, language)
        
        # Split into chunks
        lines = code.split('\n')
        chunks = []
        chunk_start = 0
        
        while chunk_start < len(lines):
            # Calculate chunk size
            chunk_end = min(chunk_start + self.max_chunk_lines, len(lines))
            
            # Try to break at function/class boundaries if possible
            if chunk_end < len(lines):
                chunk_end = self._find_good_break_point(lines, chunk_start, chunk_end, language)
            
            # Extract chunk content
            chunk_lines = lines[chunk_start:chunk_end]
            chunk_content = '\n'.join(chunk_lines)
            
            # Check token limit
            while self.estimate_tokens(chunk_content) > self.max_code_tokens and len(chunk_lines) > 10:
                # Reduce chunk size
                chunk_end = chunk_start + len(chunk_lines) - 50
                if chunk_end <= chunk_start:
                    chunk_end = chunk_start + 10
                chunk_lines = lines[chunk_start:chunk_end]
                chunk_content = '\n'.join(chunk_lines)
            
            chunks.append(CodeChunk(
                content=chunk_content,
                start_line=chunk_start + 1,
                end_line=chunk_end,
                file_path=file_path,
                chunk_index=len(chunks),
                total_chunks=0,  # Will update after
                imports=imports
            ))
            
            chunk_start = chunk_end
        
        # Update total_chunks
        for chunk in chunks:
            chunk.total_chunks = len(chunks)
        
        return chunks
    
    def _find_good_break_point(self, lines: List[str], start: int, end: int, 
                                language: str) -> int:
        """
        Find a good point to break code chunks (e.g., between functions).
        
        Args:
            lines: All lines of code
            start: Start index
            end: Proposed end index
            language: Programming language
            
        Returns:
            Better end index
        """
        # Look backwards from end for function/class definitions
        for i in range(end - 1, start, -1):
            line = lines[i].strip()
            
            if language in ["python", ".py"]:
                if line.startswith('def ') or line.startswith('class '):
                    return i
            elif language in ["javascript", "typescript", ".js", ".ts"]:
                if 'function ' in line or line.startswith('class '):
                    return i
            elif language in ["java", ".java"]:
                if line.startswith('public ') or line.startswith('private ') or line.startswith('protected '):
                    return i
        
        return end
    
    def build_context(self, chunk: CodeChunk, include_imports: bool = True) -> str:
        """
        Build context string for AI analysis.
        
        Args:
            chunk: Code chunk to build context for
            include_imports: Include import statements
            
        Returns:
            Context string with metadata
        """
        context_parts = []
        
        # File metadata
        context_parts.append(f"File: {chunk.file_path}")
        
        if chunk.total_chunks > 1:
            context_parts.append(
                f"Chunk {chunk.chunk_index + 1} of {chunk.total_chunks} "
                f"(lines {chunk.start_line}-{chunk.end_line})"
            )
        
        # Imports
        if include_imports and chunk.imports:
            context_parts.append("\nImports:")
            context_parts.extend(chunk.imports)
        
        # Code
        context_parts.append("\nCode:")
        context_parts.append(chunk.content)
        
        return '\n'.join(context_parts)
    
    def estimate_cost(self, text: str, cost_per_1m_tokens: float = 0.10) -> float:
        """
        Estimate API cost for text.
        
        Args:
            text: Text to estimate
            cost_per_1m_tokens: Cost per million tokens
            
        Returns:
            Estimated cost in dollars
        """
        tokens = self.estimate_tokens(text)
        return (tokens / 1_000_000) * cost_per_1m_tokens
    
    def get_token_stats(self, code: str) -> Dict:
        """
        Get token statistics for code.
        
        Args:
            code: Source code
            
        Returns:
            Dictionary with token statistics
        """
        tokens = self.estimate_tokens(code)
        
        return {
            "estimated_tokens": tokens,
            "token_limit": self.token_limit,
            "max_code_tokens": self.max_code_tokens,
            "usage_percentage": (tokens / self.max_code_tokens) * 100,
            "needs_chunking": self.needs_chunking(code),
            "estimated_chunks": max(1, tokens // self.max_code_tokens),
        }


if __name__ == "__main__":
    # Test context manager
    cm = ContextManager(model_name="codellama")
    
    # Test code
    test_code = """
import os
import sys
from pathlib import Path

def function1():
    # This is a test function
    pass

def function2():
    # Another function
    pass

class MyClass:
    def __init__(self):
        pass
    
    def method1(self):
        pass
""" * 20  # Make it larger
    
    # Test token estimation
    stats = cm.get_token_stats(test_code)
    print("Token Stats:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test chunking
    chunks = cm.chunk_code(test_code, "test.py", "python")
    print(f"\nCreated {len(chunks)} chunks")
    
    for i, chunk in enumerate(chunks):
        print(f"\nChunk {i + 1}:")
        print(f"  Lines: {chunk.start_line}-{chunk.end_line}")
        print(f"  Imports: {len(chunk.imports)}")
        print(f"  Length: {len(chunk.content)} chars")