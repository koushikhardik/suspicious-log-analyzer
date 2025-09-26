import re
import argparse

# Define regex patterns for common web attacks
THREAT_PATTERNS = {
    'SQL_INJECTION': re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(union\s*select)", re.IGNORECASE),
    'DIRECTORY_TRAVERSAL': re.compile(r"(\.\./)|(\.\.\\)"),
    'COMMAND_INJECTION': re.compile(r"(;|\||`|\$|\(|\)|&&|\|\|)"),
    'XSS_ATTACK': re.compile(r"(<script>)|(%3Cscript%3E)|(alert\()", re.IGNORECASE)
}

def analyze_log_file(file_path):
    """
    Analyzes a log file for suspicious patterns and prints alerts.
    """
    print(f"[INFO] Starting analysis of log file: {file_path}\n")
    found_threats = 0
    
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                for threat_type, pattern in THREAT_PATTERNS.items():
                    if pattern.search(line):
                        print(f"[ALERT] Potential {threat_type} detected on line {line_num}:")
                        print(f"   -> {line.strip()}\n")
                        found_threats += 1
                        break # Move to the next line after finding one threat
    except FileNotFoundError:
        print(f"[ERROR] Log file not found at: {file_path}")
        return

    print(f"[INFO] Analysis complete. Found {found_threats} potential threats.")

if __name__ == "__main__":
    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(description="Analyze web server logs for suspicious activity.")
    parser.add_argument("logfile", help="Path to the log file to be analyzed.")
    
    args = parser.parse_args()
    
    analyze_log_file(args.logfile)
