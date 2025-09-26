# Suspicious Web Log Analyzer

A simple, fast Python script to parse web server log files and detect common security threats like SQL Injection, Directory Traversal, and XSS attacks. This tool is designed for educational purposes to demonstrate basic log analysis techniques for security investigations.

## Features
- **SQL Injection Detection:** Identifies common SQLi patterns and keywords.
- **Directory Traversal:** Flags attempts to access restricted files using `../`.
- **Cross-Site Scripting (XSS):** Detects basic XSS payloads like `<script>` tags.
- **Command Injection:** Looks for shell command characters that may indicate an attack.

## How to Run
1. Clone the repository.
2. Make sure you have Python installed.
3. Run the script from your terminal, providing the path to a log file:
   ```bash
   python analyzer.py sample_access.log
   
