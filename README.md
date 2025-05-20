# Flyingduck-MCP

Flyingduck-MCP is an internal security scanner server that provides SAST, SCA, Secrets Scanning, and SBOM Vulnerability Analysis via modular CLI commands. It is designed for LLM and Cursor integration, enabling prompt-based security workflows.

## Features
- Fetch repositories and dependencies
- SAST, SCA, Secrets, and SBOM scanning
- Automated fix and cleanup commands
- JSON output for easy LLM/Cursor parsing
- Extensible via `mcp.config.yaml`

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python -m flyingduck_mcp.cli scan-all
python -m flyingduck_mcp.cli scan-sast
python -m flyingduck_mcp.cli scan-sbom --file ./path/to/sbom.json
```

## MCP Config
The `mcp.config.yaml` file defines all available commands, prompt mappings, and execution details for LLM and Cursor integration. See the file for details. 