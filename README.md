# CODE SENTINEL

AI-powered code vulnerability scanner using local and cloud-based AI models.

CODE SENTINEL analyzes source code using large language models to identify common security issues such as injection flaws, insecure configurations, weak cryptography, and hardcoded secrets. It is designed to be easy to run locally, while still supporting fast cloud-based scanning when needed.

---

## Features

* multi-language support (python, javascript, java, go, php, ruby, c/c++, rust, and more)
* local and cloud ai providers (ollama, groq, hugging face)
* structured findings with severity, cwe references, and line numbers
* terminal, html, and json output formats
* clean, shareable html security reports
* privacy-first: fully offline scanning with local models

---

## Requirements

* python 3.9 or higher
* optional: ollama for local inference
* optional: api keys for cloud providers

---

## Installation

```bash
git clone https://github.com/yourusername/code-sentinel.git
cd code-sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Basic Usage

```bash
# scan a directory (terminal output)
python main.py scan ./my-project

# generate an html report
python main.py scan ./my-project --format html --output report.html

# generate a json report
python main.py scan ./my-project --format json --output report.json
```

---

## AI Providers

### Local (Ollama)

Best for privacy-sensitive projects and offline use.

```bash
ollama pull codellama
python main.py scan ./my-project
```

Supported models:

* codellama
* mistral
* llama3.2
* qwen2.5-coder

---

### Groq (Cloud)

Fast cloud-based inference for larger scans.

```bash
export GROQ_API_KEY="your-key"
python main.py scan ./my-project --client groq
```

Default model:

* llama-3.3-70b-versatile

---

### Hugging Face

Useful for experimenting with different models.

```bash
export HUGGINGFACE_API_KEY="your-token"
python main.py scan ./my-project --client huggingface
```

---

## Command Line Options

```bash
python main.py scan <path> [options]

--client {ollama,groq,huggingface}
--model MODEL
--prompt {standard,detailed,quick}
--format {terminal,html,json}
--output PATH
--api-key KEY
--quiet
```

---

## Detected Vulnerabilities

CODE SENTINEL can identify issues including:

* sql injection (cwe-89)
* command injection (cwe-78)
* cross-site scripting (cwe-79)
* hardcoded secrets (cwe-798)
* weak cryptography (cwe-327)
* path traversal (cwe-22)
* insecure deserialization (cwe-502)
* security misconfiguration

---

## Configuration

Edit `config/default_config.yaml` to customize scanning behavior.

```yaml
models:
  local:
    default: codellama
  groq:
    default: llama-3.3-70b-versatile

scan:
  severity_threshold: medium
  ignore_patterns:
    - node_modules
    - .git
    - venv

output:
  format: terminal
  colors: true
```

---

## Project Status

Current version: **v0.2.0**

The project is under active development, with a focus on improving detection quality, performance, and reporting clarity.

---

## License

MIT License. See [LICENSE](LICENSE).
