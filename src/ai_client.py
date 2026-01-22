"""
AI client implementations for CODE SENTINEL.
Handles communication with local (Ollama) and cloud-based AI models.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class AIClient(ABC):
    """Abstract base class for AI clients."""
    
    def __init__(self, model: str, max_retries: int = 3, timeout: int = 60):
        """
        Initialize AI client.
        
        Args:
            model: Model name/identifier
            max_retries: Maximum number of retry attempts
            timeout: Request timeout in seconds
        """
        self.model = model
        self.max_retries = max_retries
        self.timeout = timeout
    
    @abstractmethod
    def analyze_code(self, code: str, filename: str, prompt_template: str) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities.
        
        Args:
            code: Source code to analyze
            filename: Name of the file being analyzed
            prompt_template: Prompt template to use
            
        Returns:
            Dictionary containing analysis results
        """
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to the AI service.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    def _create_session(self) -> requests.Session:
        """
        Create a requests session with retry logic.
        
        Returns:
            Configured requests session
        """
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session


class OllamaClient(AIClient):
    """Client for local Ollama AI models."""
    
    def __init__(self, model: str = "codellama", 
                 base_url: str = "http://localhost:11434",
                 max_retries: int = 3,
                 timeout: int = 120):
        """
        Initialize Ollama client.
        
        Args:
            model: Ollama model name (e.g., 'codellama', 'mistral')
            base_url: Ollama API base URL
            max_retries: Maximum retry attempts
            timeout: Request timeout in seconds
        """
        super().__init__(model, max_retries, timeout)
        self.base_url = base_url.rstrip('/')
        self.session = self._create_session()
    
    def test_connection(self) -> bool:
        """
        Test connection to Ollama service.
        
        Returns:
            True if Ollama is running and accessible
        """
        try:
            response = self.session.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m['name'] for m in models]
                print(f"✓ Connected to Ollama. Available models: {model_names}")
                
                if self.model not in model_names and not any(self.model in m for m in model_names):
                    print(f"⚠ Warning: Model '{self.model}' not found. Available: {model_names}")
                    return False
                
                return True
            return False
        except requests.exceptions.RequestException as e:
            print(f"✗ Failed to connect to Ollama: {e}")
            print(f"  Make sure Ollama is running: ollama serve")
            return False
    
    def analyze_code(self, code: str, filename: str, prompt_template: str) -> Dict[str, Any]:
        """
        Analyze code using Ollama model.
        
        Args:
            code: Source code to analyze
            filename: Name of the file
            prompt_template: Prompt template with {code} and {filename} placeholders
            
        Returns:
            Dictionary with analysis results
        """
        # Format the prompt
        prompt = prompt_template.format(code=code, filename=filename)
        
        start_time = time.time()
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,  # Lower temperature for more focused analysis
                        "top_p": 0.9,
                    }
                },
                timeout=self.timeout
            )
            
            response.raise_for_status()
            result = response.json()
            
            elapsed_time = time.time() - start_time
            
            return {
                "success": True,
                "response": result.get("response", ""),
                "model": self.model,
                "filename": filename,
                "elapsed_time": elapsed_time,
                "error": None
            }
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "response": None,
                "model": self.model,
                "filename": filename,
                "elapsed_time": time.time() - start_time,
                "error": "Request timed out"
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "response": None,
                "model": self.model,
                "filename": filename,
                "elapsed_time": time.time() - start_time,
                "error": f"Request failed: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "response": None,
                "model": self.model,
                "filename": filename,
                "elapsed_time": time.time() - start_time,
                "error": f"Unexpected error: {str(e)}"
            }
    
    def list_models(self) -> list:
        """
        List available Ollama models.
        
        Returns:
            List of model names
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [m['name'] for m in models]
            return []
        except Exception as e:
            print(f"Error listing models: {e}")
            return []


def create_client(client_type: str = "ollama", **kwargs) -> AIClient:
    """
    Factory function to create AI clients.
    
    Args:
        client_type: Type of client ('ollama', 'groq', 'huggingface')
        **kwargs: Additional arguments for the client
        
    Returns:
        AIClient instance
    """
    if client_type.lower() == "ollama":
        return OllamaClient(**kwargs)
    else:
        raise ValueError(f"Unsupported client type: {client_type}")


if __name__ == "__main__":
    # Quick test
    print("Testing Ollama connection...")
    client = OllamaClient(model="codellama")
    
    if client.test_connection():
        print("\n✓ Ollama client ready!")
        
        # Test with simple code
        test_code = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
"""
        
        print("\nTesting code analysis...")
        result = client.analyze_code(
            code=test_code,
            filename="test.py",
            prompt_template="Analyze this code for security vulnerabilities:\n\n{code}"
        )
        
        if result["success"]:
            print(f"\n✓ Analysis completed in {result['elapsed_time']:.2f}s")
            print(f"Response preview: {result['response'][:200]}...")
        else:
            print(f"\n✗ Analysis failed: {result['error']}")
    else:
        print("\n✗ Ollama connection failed")
        print("Make sure Ollama is installed and running:")
        print("  1. Install: https://ollama.ai")
        print("  2. Run: ollama serve")
        print("  3. Pull model: ollama pull codellama")