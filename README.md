# Audit Bridge MCP

Audit Bridge MCP is a Model Context Protocol (MCP) server built with TypeScript for orchestrating and managing Windows system auditing tools. It supports various system checks, configuration adjustments, and security operations through a standardized tool interface.

## Purpose

Audit Bridge MCP streamlines Windows system audits by exposing multiple tools and operations behind a unified MCP interface. It is designed for integration with MCP clients and automation workflows related to security, compliance, and administration.

## Benefits

- **Centralized Audit Management**: Unified MCP server to orchestrate various Windows system auditing tools, reducing complexity and improving operational efficiency.
- **Standardized Interface**: All audit-related tools and commands exposed through a standardized Model Context Protocol interface, making integration with MCP clients straightforward.
- **Modular and Extensible**: Modular file structure enables easy maintenance and future expansion with additional tools or features.
- **Remote Automation**: Supports remote audit operations via SSH, allowing administrators to manage and audit multiple Windows systems from a single location.
- **Security and Compliance**: Facilitates security checks (firewall status, admin rights verification, registry audits) to help maintain compliance with organizational or regulatory requirements.
- **Flexibility**: Enables both automated and manual security checks, supporting various use cases from routine audits to incident response.
- **Efficiency**: Reduces manual effort and potential for human error by automating repetitive system checks and configuration verifications.

## Requirements

- [Python](https://www.python.org/) 3.8 or higher
- Required Python packages (installed via `pip install -r requirements.txt`):
    - paramiko (for SSH connections)
    - fastmcp (for MCP server implementation)
- Remote computer(s) must have **SSH enabled**
- The user account used for SSH must have **administrative rights** on the remote computer
- Windows operating system on target machines

## File Structure

```
/
├── main.py                 # MCP server entry point
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── utilities/              # Core functionality modules
    ├── batFileContentHandler.py # content of all the bat files that needs to be imported
    └── manualGuidesHandler.py   # content of all the manual guides
```


## Features

- Exposes multiple tools via the Model Context Protocol (MCP):
  - Symantec status checker
  - Manual security guides
  - Admin rights verification
  - Firewall control (enable/disable/status)
  - Registry key audit and modifications
  - Remote audit setup (e.g., via `.bat` files)
 
## Limitation
- currently running commands through SSH

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Shangwee/PY-Audit-Bridge.git
cd PY-Audit-Bridge
pip install -r requirements.txt
```

## Usage

Integrate with your MCP client by referencing the built server:

```json
{
  "mcpServers": {
    "audit-bridge-mcp": {
      "command": "fastmcp run",
      "args": ["/path/to/PY-Audit-Bridge/main.py"]
    }
  }
}
```

Replace `/path/to/PY-Audit-Bridge/main.py` with the actual path to your built server.
