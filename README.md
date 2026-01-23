
# CODE SENTINEL

AI-powered code vulnerability scanner in Python with support for local (Ollama) and cloud-based AI models.

## Features

- 🔍 **Multi-language support**: Python, JavaScript, Java, Go, PHP, Ruby, C/C++, Rust, and more
- 🤖 **Multiple AI providers**: Local (Ollama), Cloud (Groq, Hugging Face)
- 📊 **Structured vulnerability reports**: Severity levels, CWE references, line numbers
- 📄 **Multiple output formats**: Terminal, HTML, JSON
- 🎨 **Beautiful HTML reports**: Professional, shareable security reports
- 💡 **Detailed findings**: Code snippets, descriptions, and fix recommendations
- ⚡ **Fast scanning**: Parallel processing and smart caching
- 🔒 **Privacy-first**: Use local models for complete privacy

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
# Scan with terminal output (default)
python main.py scan ./my-project

# Generate HTML report
python main.py scan ./my-project --format html --output report.html

# Generate JSON report
python main.py scan ./my-project --format json --output report.json

# Scan with Groq (fast cloud model)
export GROQ_API_KEY="your-api-key"
python main.py scan ./my-project --client groq --format html --output report.html

# Use detailed analysis prompt
python main.py scan ./my-project --prompt detailed
```

## Output Formats

### Terminal Output
Interactive, color-coded output with progress bars and detailed vulnerability breakdown.

```bash
python main.py scan ./project
```

### HTML Report
Professional HTML report with:
- Beautiful gradient design
- Color-coded severity badges
- Summary statistics dashboard
- Detailed vulnerability cards
- Code snippets with syntax highlighting
- Actionable recommendations

```bash
python main.py scan ./project --format html --output report.html
```

![HTML Report Example](<img width="1148" height="608" alt="Screenshot 2026-01-23 at 18 58 30" src="https://github.com/user-attachments/assets/a08e5f7c-b0d9-4db7-90d9-f6916b74d157" />)

### JSON Report
Machine-readable format perfect for:
- CI/CD integration
- Custom processing
- Data analysis
- Integration with other tools

```bash
python main.py scan ./project --format json --output report.json
```

## AI Provider Options

### 🏠 Local (Ollama) - Default
**Pros:** Free, private, no API limits  
**Cons:** Requires local installation, slower  
**Best for:** Privacy-sensitive projects, offline scanning

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
**Best for:** Fast scans, CI/CD pipelines, team collaboration

**Setup:**
```bash
# Get free API key from https://console.groq.com
export GROQ_API_KEY="your-key"
python main.py scan ./my-project --client groq
```

**Available models:** 
- `llama-3.3-70b-versatile` (default, best quality)
- `mixtral-8x7b-32768`
- `gemma2-9b-it`

**Free tier limits:**
- 14,400 requests/day
- 30 requests/minute
- 7,000 tokens/minute

### 🤗 Hugging Face
**Pros:** Wide model selection  
**Cons:** Free tier limited, slower, some models gated  
**Best for:** Experimenting with different models

**Setup:**
```bash
export HUGGINGFACE_API_KEY="your-token"
python main.py scan ./my-project --client huggingface
```

## Command Line Options

```bash
python main.py scan <path> [options]

Required:
  <path>                          Path to file or directory to scan

Options:
  --client {ollama,groq,huggingface}
                                  AI provider (default: ollama)
  --model MODEL                   Specific model to use
                                  Defaults: codellama (ollama),
                                           llama-3.3-70b-versatile (groq)
  --prompt {standard,detailed,quick}
                                  Analysis depth (default: standard)
  --format {terminal,html,json}   Output format (default: terminal)
  --output PATH                   Output file path (required for html/json)
  --api-key KEY                   API key for cloud providers
  --quiet                         Minimal output
```

## Examples

```bash
# Quick scan with terminal output
python main.py scan ./src

# Detailed analysis with HTML report
python main.py scan ./src --prompt detailed --format html --output security-report.html

# Fast Groq scan with JSON export
python main.py scan ./src --client groq --format json --output results.json

# Scan single file
python main.py scan app.py --client groq

# Custom model
python main.py scan ./src --client groq --model mixtral-8x7b-32768
```

## Vulnerability Detection

CODE SENTINEL detects 50+ vulnerability types including:

**Injection Flaws:**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Code Injection (CWE-94)
- LDAP Injection (CWE-90)

**Cross-Site Scripting:**
- Reflected XSS (CWE-79)
- Stored XSS (CWE-79)
- DOM-based XSS

**Authentication & Session:**
- Broken Authentication (CWE-287)
- Session Fixation (CWE-384)
- Weak Password Storage (CWE-916)

**Cryptography:**
- Weak Encryption (CWE-327)
- Hardcoded Secrets (CWE-798)
- Insecure Random (CWE-338)

**Access Control:**
- Path Traversal (CWE-22)
- Insecure Deserialization (CWE-502)
- Authorization Bypass

**Configuration:**
- Security Misconfiguration
- Exposed Sensitive Data
- Verbose Error Messages

## Configuration

Edit `config/default_config.yaml` to customize:

```yaml
# AI Model Settings
models:
  groq:
    default: "llama-3.3-70b-versatile"
  local:
    default: "codellama"
  
# Scanning Options
scan:
  severity_threshold: "medium"
  file_types: [".py", ".js", ".java", ".go", ".php"]
  ignore_patterns: ["node_modules", ".git", "venv"]
  default_prompt: "standard"

# Output Settings
output:
  verbose: true
  format: "terminal"
  colors: true
```

## Project Status

**Current Version:** v0.2.0

### Completed Milestones

✅ **Phase 1: Foundation**
- Project structure and file handling
- Basic AI client (Ollama)
- File parser with multi-language support

✅ **Phase 2: AI Integration** (In Progress)
- ✅ Milestone 2.1: Structured JSON output
- ✅ Milestone 2.2: Multi-model support (Groq, HuggingFace)
- ✅ **NEW:** HTML and JSON report generation
- ⏳ Milestone 2.3: Context management

### Upcoming

⏳ **Phase 3: Core Features**
- CLI enhancements
- Caching system
- Configuration management

⏳ **Phase 4: Reporting & Output**
- Markdown reports
- SARIF format (GitHub integration)
- Statistics and trends

⏳ **Phase 5: Advanced Features**
- Baseline comparison
- CI/CD integration
- Performance optimization

⏳ **Phase 6: Distribution**
- PyPI package
- Docker image
- Documentation site

## Development

### Run Tests
```bash
pytest tests/
```

### Scan the Project Itself
```bash
python main.py scan ./src --prompt detailed --format html --output self-scan.html
```

### Test with Vulnerable Code
```bash
python main.py scan ./tests_vulnerable/
```

### Code Formatting
```bash
black src/ tests/
ruff check src/ tests/
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install CODE SENTINEL
        run: |
          pip install -r requirements.txt
      
      - name: Run Security Scan
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: |
          python main.py scan ./src --client groq --format json --output results.json
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: results.json
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

**Getting API Keys:**
- **Groq:** https://console.groq.com (Free, instant signup)
- **Hugging Face:** https://huggingface.co/settings/tokens (Free)

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Ollama](https://ollama.ai/) for local AI inference
- [Groq](https://groq.com/) for fast cloud inference
- Inspired by [Kubescape](https://github.com/kubescape/kubescape) and industry-leading security tools
- Powered by the open-source community

## Support & Resources

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/yourusername/code-sentinel/issues)
- 💬 [Discussions](https://github.com/yourusername/code-sentinel/discussions)
- 🌐 [Groq Console](https://console.groq.com) - Get free API key
- 🤗 [Hugging Face](https://huggingface.co/settings/tokens) - Get API token
- 🦙 [Ollama](https://ollama.ai) - Download local models

## Roadmap

- [ ] Markdown report format
- [ ] SARIF format for GitHub Security
- [ ] Baseline comparison
- [ ] Custom rule engine
- [ ] VS Code extension
- [ ] Docker image
- [ ] PyPI package
- [ ] Web dashboard

---

**Made with ❤️ by the CODE SENTINEL team**

*Secure your code with AI-powered vulnerability detection*
