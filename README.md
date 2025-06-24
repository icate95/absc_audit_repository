# ABSC Audit System

## Overview

The ABSC Audit System is a comprehensive, automated security audit tool designed to assess and verify compliance with the AgID Basic Security Controls (ABSC) across various IT infrastructure components.

## Key Features

- 🔒 Multi-platform support (Linux, Windows, macOS)
- 📊 Comprehensive security checks
- 🤖 Automated audit execution
- 📈 Detailed reporting
- 🛡️ Flexible and extensible architecture

## Installation

### Prerequisites

- Python 3.8+
- pip
- Virtual environment (recommended)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/absc-audit-system.git
cd absc-audit-system
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/macOS
# Or
venv\Scripts\activate.bat  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -e .
```

4. Initialize the system:
```bash
absc-audit init-db
```

## Usage

### Quick Start

Add a target:
```bash
absc-audit add-target --name "Web Server" --hostname 192.168.1.100 --os linux
```

Run an audit:
```bash
absc-audit run-audit --target "Web Server"
```

Generate a report:
```bash
absc-audit generate-report --target "Web Server" --format html
```

## Available Commands

- `add-target`: Register a new audit target
- `list-targets`: Show all registered targets
- `list-checks`: Display available security checks
- `run-check`: Execute a specific security check
- `run-audit`: Perform a comprehensive audit
- `generate-report`: Create audit reports

## Security Checks Covered

- Inventory Management
- Vulnerability Assessment
- Authentication Controls
- Access Management
- Backup Procedures
- Logging and Monitoring
- Encryption Verification
- Malware Protection

## Acknowledgements

- AgID (Agenzia per l'Italia Digitale)
- Open Source Security Community