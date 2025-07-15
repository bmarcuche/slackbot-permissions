#!/usr/bin/env python3
"""
Security Audit Script for Slackbot Permissions

This script scans the codebase for potential security issues including:
- Hardcoded secrets or tokens
- Personal information
- Insecure configurations
- Missing security best practices
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple


class SecurityAuditor:
    """Performs security audit of the codebase."""
    
    # Patterns that might indicate hardcoded secrets
    SECRET_PATTERNS = [
        (r'xoxb-(?!your-|replace-|example-|test-)[a-zA-Z0-9-]+', 'Slack Bot Token'),
        (r'xoxp-(?!your-|replace-|example-|test-)[a-zA-Z0-9-]+', 'Slack User Token'),
        (r'xapp-(?!your-|replace-|example-|test-)[a-zA-Z0-9-]+', 'Slack App Token'),
        (r'sk-(?!your-|replace-|example-|test-)[a-zA-Z0-9]{48}', 'OpenAI API Key'),
        (r'ghp_(?!your-|replace-|example-|test-)[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
        (r'gho_(?!your-|replace-|example-|test-)[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'["\']?password["\']?\s*[:=]\s*["\'](?!your-|replace-|example-|test-|placeholder)[^"\']{8,}["\']', 'Hardcoded Password'),
        (r'["\']?secret["\']?\s*[:=]\s*["\'](?!your-|replace-|example-|test-|placeholder)[^"\']{8,}["\']', 'Hardcoded Secret'),
        (r'["\']?api_key["\']?\s*[:=]\s*["\'](?!your-|replace-|example-|test-|placeholder)[^"\']{8,}["\']', 'Hardcoded API Key'),
    ]
    
    # Patterns for personal information
    PERSONAL_INFO_PATTERNS = [
        (r'(?!.*@(?:example\.com|company\.com|test\.com))[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN Pattern'),
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'Credit Card Pattern'),
    ]
    
    # File extensions to scan
    SCAN_EXTENSIONS = {'.py', '.md', '.txt', '.yml', '.yaml', '.json', '.sh'}
    
    # Directories to skip
    SKIP_DIRS = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv'}
    
    def __init__(self, root_path: str):
        """Initialize auditor with root path."""
        self.root_path = Path(root_path)
        self.issues: List[Dict] = []
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a single file for security issues."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Check for secrets
            for pattern, description in self.SECRET_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    issues.append({
                        'type': 'SECRET',
                        'file': str(file_path.relative_to(self.root_path)),
                        'line': line_num,
                        'description': description,
                        'severity': 'HIGH',
                        'content': lines[line_num - 1].strip()[:100]
                    })
            
            # Check for personal information
            for pattern, description in self.PERSONAL_INFO_PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    # Skip if it's in a comment, example, or documentation
                    line_content = lines[line_num - 1].strip()
                    skip_markers = ['example', 'your-', 'placeholder', '#', 'replace-', 'test-', 'company.com', 'DON\'T DO THIS']
                    if not any(marker in line_content.lower() for marker in skip_markers):
                        issues.append({
                            'type': 'PERSONAL_INFO',
                            'file': str(file_path.relative_to(self.root_path)),
                            'line': line_num,
                            'description': description,
                            'severity': 'MEDIUM',
                            'content': line_content[:100]
                        })
        
        except Exception as e:
            issues.append({
                'type': 'ERROR',
                'file': str(file_path.relative_to(self.root_path)),
                'line': 0,
                'description': f'Error reading file: {e}',
                'severity': 'LOW',
                'content': ''
            })
        
        return issues
    
    def scan_directory(self) -> None:
        """Scan entire directory tree."""
        for root, dirs, files in os.walk(self.root_path):
            # Skip certain directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            
            for file in files:
                file_path = Path(root) / file
                
                # Only scan certain file types
                if file_path.suffix in self.SCAN_EXTENSIONS:
                    file_issues = self.scan_file(file_path)
                    self.issues.extend(file_issues)
    
    def check_gitignore(self) -> List[Dict]:
        """Check if .gitignore has proper security entries."""
        issues = []
        gitignore_path = self.root_path / '.gitignore'
        
        if not gitignore_path.exists():
            issues.append({
                'type': 'MISSING_FILE',
                'file': '.gitignore',
                'line': 0,
                'description': 'Missing .gitignore file',
                'severity': 'MEDIUM',
                'content': ''
            })
            return issues
        
        try:
            with open(gitignore_path, 'r') as f:
                gitignore_content = f.read()
            
            required_patterns = ['.env', '*.key', '*.pem', 'secrets.*']
            missing_patterns = []
            
            for pattern in required_patterns:
                if pattern not in gitignore_content:
                    missing_patterns.append(pattern)
            
            if missing_patterns:
                issues.append({
                    'type': 'GITIGNORE',
                    'file': '.gitignore',
                    'line': 0,
                    'description': f'Missing security patterns: {", ".join(missing_patterns)}',
                    'severity': 'MEDIUM',
                    'content': ''
                })
        
        except Exception as e:
            issues.append({
                'type': 'ERROR',
                'file': '.gitignore',
                'line': 0,
                'description': f'Error reading .gitignore: {e}',
                'severity': 'LOW',
                'content': ''
            })
        
        return issues
    
    def generate_report(self) -> str:
        """Generate security audit report."""
        if not self.issues:
            return "✅ No security issues found!"
        
        report = ["🔍 Security Audit Report", "=" * 50, ""]
        
        # Group by severity
        high_issues = [i for i in self.issues if i['severity'] == 'HIGH']
        medium_issues = [i for i in self.issues if i['severity'] == 'MEDIUM']
        low_issues = [i for i in self.issues if i['severity'] == 'LOW']
        
        if high_issues:
            report.extend(["🚨 HIGH SEVERITY ISSUES", "-" * 30])
            for issue in high_issues:
                report.append(f"File: {issue['file']}:{issue['line']}")
                report.append(f"Issue: {issue['description']}")
                report.append(f"Content: {issue['content']}")
                report.append("")
        
        if medium_issues:
            report.extend(["⚠️  MEDIUM SEVERITY ISSUES", "-" * 30])
            for issue in medium_issues:
                report.append(f"File: {issue['file']}:{issue['line']}")
                report.append(f"Issue: {issue['description']}")
                if issue['content']:
                    report.append(f"Content: {issue['content']}")
                report.append("")
        
        if low_issues:
            report.extend(["ℹ️  LOW SEVERITY ISSUES", "-" * 30])
            for issue in low_issues:
                report.append(f"File: {issue['file']}:{issue['line']}")
                report.append(f"Issue: {issue['description']}")
                report.append("")
        
        # Summary
        report.extend([
            "📊 SUMMARY",
            "-" * 30,
            f"Total Issues: {len(self.issues)}",
            f"High Severity: {len(high_issues)}",
            f"Medium Severity: {len(medium_issues)}",
            f"Low Severity: {len(low_issues)}",
            "",
            "🔧 RECOMMENDATIONS",
            "-" * 30,
            "1. Remove any hardcoded secrets and use environment variables",
            "2. Update .gitignore to exclude sensitive files",
            "3. Use configuration management for sensitive data",
            "4. Review and remove any personal information",
            "5. Implement proper secret management in production"
        ])
        
        return "\n".join(report)


def main():
    """Main function to run security audit."""
    if len(sys.argv) > 1:
        root_path = sys.argv[1]
    else:
        root_path = os.getcwd()
    
    print(f"🔍 Running security audit on: {root_path}")
    print("=" * 60)
    
    auditor = SecurityAuditor(root_path)
    
    # Scan files
    auditor.scan_directory()
    
    # Check gitignore
    gitignore_issues = auditor.check_gitignore()
    auditor.issues.extend(gitignore_issues)
    
    # Generate and print report
    report = auditor.generate_report()
    print(report)
    
    # Exit with error code if high severity issues found
    high_severity_count = len([i for i in auditor.issues if i['severity'] == 'HIGH'])
    if high_severity_count > 0:
        print(f"\n❌ Security audit failed with {high_severity_count} high severity issues")
        sys.exit(1)
    else:
        print("\n✅ Security audit passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
