# CODE SENTINEL

AI-powered code vulnerability scanner using local and cloud-based AI models.

## Features

- **Multi-language support**: Python, JavaScript, Java, Go, PHP, Ruby, C/C++, Rust, and more
- **Multiple AI providers**: Local (Ollama), Cloud (Groq, Hugging Face)
- **Structured vulnerability reports**: Severity levels, CWE references, line numbers
- **Beautiful terminal output**: Color-coded findings with detailed recommendations
- **Fast scanning**: Parallel processing and smart caching
- **Privacy-first**: Use local models for complete privacy

## Quick Start

### Prerequisites

- Python 3.9 or higher
- (Optional) [Ollama](https://ollama.ai) for local scanning
- (Optional) API keys for cloud providers

### Installation

```bash
git clone https://github.com/stasdot/code-sentinel.git
cd code-sentinel
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan with local Ollama (default)
python main.py scan ./my-project

# Scan with Groq (fast, free cloud model)
export GROQ_API_KEY="your-api-key"
python main.py scan ./my-project --client groq

# Scan single file with detailed analysis
python main.py scan app.py --prompt detailed

# Quiet mode
python main.py scan ./my-project --quiet
```

## AI Provider Options

### 🏠 Local (Ollama) - Default
**Pros:** Free, private, no API limits  
**Cons:** Requires local installation, slower  
**Setup:**
```bash
# Install Ollama from https://ollama.ai
ollama pull codellama
python main.py scan ./my-project
```

**Available models:** `codellama`, `mistral`, `llama3.2`, `qwen2.5-coder`

### ⚡ Groq (Recommended for Cloud)
**Pros:** Very fast, generous free tier (14,400 requests/day)  
**Cons:** Requires API key, rate limits  
**Setup:**
```bash
# Get free API key from https://console.groq.com
export GROQ_API_KEY="your-key"
python main.py scan ./my-project --client groq
```

**Available models:** `llama-3.3-70b-versatile` (default), `mixtral-8x7b-32768`, `gemma2-9b-it`

### 🤗 Hugging Face
**Pros:** Wide model selection  
**Cons:** Free tier limited, slower  
**Setup:**
```bash
export HUGGINGFACE_API_KEY="your-token"
python main.py scan ./my-project --client huggingface
```

## Command Line Options

```bash
python main.py scan <path> [options]

Options:
  --client {ollama,groq,huggingface}  AI provider (default: ollama)
  --model MODEL                       Specific model to use
  --prompt {standard,detailed,quick}  Analysis depth (default: standard)
  --api-key KEY                       API key for cloud providers
  --quiet                             Minimal output
```

## Example Output

```
╭───── 🛡️  Starting Scan ──────╮
│ CODE SENTINEL               │
│ AI-Powered Security Scanner │
│ Model: llama-3.3-70b        │
│ Client: groq                │
╰─────────────────────────────╯

🔍 Found 42 files to scan

          Scan Summary           
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric                ┃ Value ┃
┣━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━┫
│ Total Files           │ 42    │
│ Total Vulnerabilities │ 8     │
│ By Severity:          │       │
│   Critical            │ 2     │
│   High                │ 3     │
│   Medium              │ 3     │
└───────────────────────┴───────┘

═══ Vulnerability Details ═══

📄 auth.py
1. 🔴 SQL Injection (CRITICAL)
   Line: 45
   CWE: CWE-89
   
   Description:
   User input directly concatenated into SQL query
   
   ✓ Recommendation:
   Use parameterized queries or ORM
```

## Supported Vulnerability Types

CODE SENTINEL detects 50+ vulnerability types including:

- **Injection Flaws**: SQL, Command, Code injection
- **Authentication Issues**: Weak passwords, broken auth
- **XSS**: Cross-site scripting vulnerabilities
- **Cryptography**: Weak encryption, hardcoded secrets
- **Path Traversal**: Directory traversal attacks
- **Insecure Deserialization**
- **Security Misconfiguration**
- And many more...

## Configuration

Edit `config/default_config.yaml` to customize:

```yaml
models:
  groq:
    default: "llama-3.3-70b-versatile"
  
scan:
  severity_threshold: "medium"
  file_types: [".py", ".js", ".java", ".go"]
  ignore_patterns: ["node_modules", ".git", "venv"]
```

## Development

```bash
# Run tests
pytest

# Scan the project itself
python main.py scan ./src --prompt detailed

# Test with vulnerable code
python main.py scan ./tests_vulnerable/
```

## API Keys

Set as environment variables:
```bash
export GROQ_API_KEY="your-groq-key"
export HUGGINGFACE_API_KEY="your-hf-token"
```

Or pass via command line:
```bash
python main.py scan ./project --client groq --api-key "your-key"
```

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Links

- 🌐 [Groq Console](https://console.groq.com) - Get free API key
- 🤗 [Hugging Face](https://huggingface.co/settings/tokens) - Get API token
- 🦙 [Ollama](https://ollama.ai) - Download local models
- 📖 [Documentation](docs/) - Full documentation

---