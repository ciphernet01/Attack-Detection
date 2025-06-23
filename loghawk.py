import re
from collections import defaultdict

# Common attack patterns
sqli_patterns = [r"(\%27)|(\')|(\-\-)|(\%23)|(#)"]
traversal_patterns = [r"\.\./", r"%2e%2e%2f"]
brute_force_ips = defaultdict(int)

def detect_attacks(logfile):
    with open(logfile, "r") as file:
        logs = file.readlines()

    for line in logs:
        ip = line.split(" ")[0]
        url = line.split("\"")[1] if "\"" in line else ""

        # SQLi
        for pattern in sqli_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                print(f"[SQLi] Potential SQL Injection from {ip}: {url}")

        # Directory Traversal
        for pattern in traversal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                print(f"[Traversal] Potential Path Traversal from {ip}: {url}")

        # Brute Force Login
        if "POST /login" in line or "/wp-login.php" in line:
            brute_force_ips[ip] += 1
            if brute_force_ips[ip] > 10:
                print(f"[Brute Force] IP {ip} attempted login {brute_force_ips[ip]} times")

        # Suspicious User-Agents
        if any(ua in line.lower() for ua in ["sqlmap", "curl", "nmap", "wget"]):
            print(f"[Recon] Suspicious user-agent from {ip}: {line.strip()}")

        # Common error codes
        if " 404 " in line or " 403 " in line or " 500 " in line:
            print(f"[Error] {ip} got error response: {line.strip()}")

if __name__ == "__main__":
    file_path = input("Enter path to Apache log file: ")
    detect_attacks(file_path)
