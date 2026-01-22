"""
File discovery and parsing module for CODE SENTINEL.
Handles walking directories, filtering files, and reading code.
"""

import os
from pathlib import Path
from typing import List, Set, Optional
import chardet


class FileParser:
    """Handles file discovery and reading for code scanning."""
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.jsx', '.ts', '.tsx',  # Python, JavaScript, TypeScript
        '.java', '.kt',  # Java, Kotlin
        '.go',  # Go
        '.php',  # PHP
        '.rb',  # Ruby
        '.cs',  # C#
        '.cpp', '.c', '.h', '.hpp',  # C/C++
        '.rs',  # Rust
        '.swift',  # Swift
        '.sql',  # SQL
        '.sh', '.bash',  # Shell scripts
    }
    
    # Directories and patterns to ignore
    IGNORE_PATTERNS = {
        'node_modules',
        '.git',
        '.svn',
        '__pycache__',
        'venv',
        'env',
        '.venv',
        'virtualenv',
        '.pytest_cache',
        '.mypy_cache',
        'dist',
        'build',
        '.idea',
        '.vscode',
        'coverage',
        '.next',
        'target',  # Rust, Java
        'bin',
        'obj',
    }
    
    def __init__(self, custom_extensions: Optional[Set[str]] = None,
                 custom_ignores: Optional[Set[str]] = None):
        """
        Initialize the FileParser.
        
        Args:
            custom_extensions: Additional file extensions to scan
            custom_ignores: Additional patterns to ignore
        """
        self.extensions = self.SUPPORTED_EXTENSIONS.copy()
        if custom_extensions:
            self.extensions.update(custom_extensions)
        
        self.ignore_patterns = self.IGNORE_PATTERNS.copy()
        if custom_ignores:
            self.ignore_patterns.update(custom_ignores)
    
    def should_ignore(self, path: Path) -> bool:
        """
        Check if a path should be ignored.
        
        Args:
            path: Path to check
            
        Returns:
            True if path should be ignored
        """
        parts = path.parts
        return any(pattern in parts for pattern in self.ignore_patterns)
    
    def is_supported_file(self, path: Path) -> bool:
        """
        Check if a file is supported for scanning.
        
        Args:
            path: File path to check
            
        Returns:
            True if file should be scanned
        """
        return path.suffix.lower() in self.extensions
    
    def discover_files(self, root_path: str) -> List[Path]:
        """
        Discover all scannable files in a directory tree.
        
        Args:
            root_path: Root directory to scan
            
        Returns:
            List of Path objects for scannable files
        """
        root = Path(root_path).resolve()
        files = []
        
        if root.is_file():
            # If given a single file, just return it if supported
            if self.is_supported_file(root) and not self.should_ignore(root):
                files.append(root)
            return files
        
        # Walk directory tree
        for current_dir, dirnames, filenames in os.walk(root):
            current_path = Path(current_dir)
            
            # Skip ignored directories
            if self.should_ignore(current_path):
                dirnames.clear()  # Don't descend into this directory
                continue
            
            # Filter out ignored subdirectories
            dirnames[:] = [d for d in dirnames 
                          if not self.should_ignore(current_path / d)]
            
            # Add supported files
            for filename in filenames:
                file_path = current_path / filename
                if self.is_supported_file(file_path) and not self.should_ignore(file_path):
                    files.append(file_path)
        
        return sorted(files)
    
    def read_file(self, path: Path) -> Optional[str]:
        """
        Read file content with encoding detection.
        
        Args:
            path: Path to file
            
        Returns:
            File content as string, or None if read failed
        """
        try:
            # Try UTF-8 first (most common)
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Fall back to encoding detection
            try:
                with open(path, 'rb') as f:
                    raw_data = f.read()
                    result = chardet.detect(raw_data)
                    encoding = result['encoding']
                    
                if encoding:
                    return raw_data.decode(encoding)
                else:
                    print(f"Warning: Could not detect encoding for {path}")
                    return None
            except Exception as e:
                print(f"Error reading {path}: {e}")
                return None
        except Exception as e:
            print(f"Error reading {path}: {e}")
            return None
    
    def get_file_info(self, path: Path) -> dict:
        """
        Get metadata about a file.
        
        Args:
            path: Path to file
            
        Returns:
            Dictionary with file metadata
        """
        stat = path.stat()
        return {
            'path': str(path),
            'name': path.name,
            'extension': path.suffix,
            'size': stat.st_size,
            'modified': stat.st_mtime,
        }


if __name__ == "__main__":
    # Quick test
    parser = FileParser()
    
    # Test on current directory
    files = parser.discover_files('.')
    print(f"Found {len(files)} files to scan:")
    for f in files[:10]:  # Show first 10
        print(f"  - {f}")
    
    if files:
        print(f"\nReading first file: {files[0]}")
        content = parser.read_file(files[0])
        if content:
            print(f"Successfully read {len(content)} characters")