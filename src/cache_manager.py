"""
Caching system for CODE SENTINEL.
Stores scan results to avoid re-scanning unchanged files.
"""

import sqlite3
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from .models import ScanResult, Vulnerability, Severity


class CacheManager:
    """Manages caching of scan results."""
    
    def __init__(self, cache_dir: str = ".code-sentinel-cache"):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory to store cache database
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "scan_cache.db"
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                file_path TEXT PRIMARY KEY,
                file_hash TEXT NOT NULL,
                model_used TEXT NOT NULL,
                prompt_type TEXT NOT NULL,
                scan_time REAL,
                scanned_at TEXT,
                result_json TEXT NOT NULL
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_file_hash 
            ON scan_cache(file_hash)
        """)
        
        conn.commit()
        conn.close()
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA256 hash of file content.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex digest of file hash
        """
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return ""
    
    def get_cached_result(self, file_path: str, model_used: str, 
                         prompt_type: str) -> Optional[ScanResult]:
        """
        Get cached scan result if available and valid.
        
        Args:
            file_path: Path to file
            model_used: AI model identifier
            prompt_type: Prompt type used
            
        Returns:
            Cached ScanResult or None if not found/invalid
        """
        # Calculate current file hash
        current_hash = self._calculate_file_hash(file_path)
        if not current_hash:
            return None
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT file_hash, result_json
            FROM scan_cache
            WHERE file_path = ? AND model_used = ? AND prompt_type = ?
        """, (file_path, model_used, prompt_type))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        cached_hash, result_json = row
        
        # Check if file has changed
        if cached_hash != current_hash:
            # File changed, cache invalid
            return None
        
        # Deserialize result
        try:
            result_data = json.loads(result_json)
            return self._deserialize_result(result_data)
        except Exception as e:
            print(f"Error deserializing cached result: {e}")
            return None
    
    def cache_result(self, file_path: str, model_used: str, 
                    prompt_type: str, result: ScanResult):
        """
        Cache scan result.
        
        Args:
            file_path: Path to file
            model_used: AI model identifier
            prompt_type: Prompt type used
            result: Scan result to cache
        """
        file_hash = self._calculate_file_hash(file_path)
        if not file_hash:
            return
        
        result_json = json.dumps(self._serialize_result(result))
        scanned_at = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO scan_cache 
            (file_path, file_hash, model_used, prompt_type, scan_time, scanned_at, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (file_path, file_hash, model_used, prompt_type, 
              result.scan_time, scanned_at, result_json))
        
        conn.commit()
        conn.close()
    
    def invalidate_file(self, file_path: str):
        """
        Invalidate cache for a specific file.
        
        Args:
            file_path: Path to file
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_cache WHERE file_path = ?", (file_path,))
        conn.commit()
        conn.close()
    
    def clear_cache(self):
        """Clear entire cache."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_cache")
        conn.commit()
        conn.close()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM scan_cache")
        total_entries = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT model_used, COUNT(*) 
            FROM scan_cache 
            GROUP BY model_used
        """)
        by_model = dict(cursor.fetchall())
        
        cursor.execute("""
            SELECT SUM(scan_time) FROM scan_cache
        """)
        total_time_saved = cursor.fetchone()[0] or 0.0
        
        conn.close()
        
        return {
            "total_entries": total_entries,
            "by_model": by_model,
            "total_time_saved": total_time_saved,
            "cache_size_mb": self.db_path.stat().st_size / (1024 * 1024)
        }
    
    def _serialize_result(self, result: ScanResult) -> Dict:
        """Serialize ScanResult to dictionary."""
        return {
            "file_path": result.file_path,
            "vulnerabilities": [
                {
                    "type": v.type,
                    "severity": v.severity.value,
                    "line": v.line,
                    "code_snippet": v.code_snippet,
                    "description": v.description,
                    "recommendation": v.recommendation,
                    "cwe_id": v.cwe_id,
                    "confidence": v.confidence
                }
                for v in result.vulnerabilities
            ],
            "scan_time": result.scan_time,
            "model_used": result.model_used,
            "success": result.success,
            "error": result.error
        }
    
    def _deserialize_result(self, data: Dict) -> ScanResult:
        """Deserialize dictionary to ScanResult."""
        vulnerabilities = [
            Vulnerability(
                type=v["type"],
                severity=Severity(v["severity"]),
                line=v["line"],
                code_snippet=v["code_snippet"],
                description=v["description"],
                recommendation=v["recommendation"],
                cwe_id=v.get("cwe_id"),
                confidence=v.get("confidence", 1.0)
            )
            for v in data.get("vulnerabilities", [])
        ]
        
        return ScanResult(
            file_path=data["file_path"],
            vulnerabilities=vulnerabilities,
            scan_time=data["scan_time"],
            model_used=data["model_used"],
            success=data["success"],
            error=data.get("error")
        )


if __name__ == "__main__":
    # Test cache manager
    cache = CacheManager()
    
    # Get stats
    stats = cache.get_cache_stats()
    print("Cache Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\nCache database: {cache.db_path}")