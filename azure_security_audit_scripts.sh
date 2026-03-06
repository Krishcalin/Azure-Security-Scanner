#!/usr/bin/env bash
# ============================================================================
# Azure Cloud Security Audit — Base Testing Script
# Aligned to: CIS Microsoft Azure Foundations Benchmark v4.0.0
# Requirements: Azure CLI 2.50+, Python 3.8+, logged-in az session
# Usage: bash azure_security_audit_scripts.sh [--subscription <id>]
# Author: Krishnendu De
# ============================================================================

set -euo pipefail

# ── Parse optional arguments ────────────────────────────────────────────────
SUBSCRIPTION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscription) SUBSCRIPTION="$2"; shift 2 ;;
        *) echo "Usage: $0 [--subscription <subscription-id>]"; exit 1 ;;
    esac
done

# ── Azure context ───────────────────────────────────────────────────────────
if [ -n "$SUBSCRIPTION" ]; then
    az account set --subscription "$SUBSCRIPTION" 2>/dev/null
fi

ACCOUNT_INFO=$(az account show --output json 2>/dev/null) || { echo "ERROR: Not logged in. Run 'az login' first."; exit 1; }
SUB_ID=$(echo "$ACCOUNT_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
SUB_NAME=$(echo "$ACCOUNT_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['name'])")
TENANT_ID=$(echo "$ACCOUNT_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['tenantId'])")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="azure_audit_${SUB_ID:0:8}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
export OUTPUT_DIR

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

log()  { echo -e "${BLUE}[*]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

echo "======================================================================"
echo " Azure Cloud Security Audit — Base Script"
echo " Subscription : $SUB_NAME ($SUB_ID)"
echo " Tenant       : $TENANT_ID"
echo " Output       : $OUTPUT_DIR"
echo " Benchmark    : CIS Microsoft Azure Foundations v4.0.0"
echo "======================================================================"
echo ""


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: IDENTITY & ACCESS MANAGEMENT (CIS 6.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 1: IDENTITY & ACCESS MANAGEMENT ══${NC}"

log "IAM-01: Checking Security Defaults status (CIS 6.1.1)"
python3 - <<'PYEOF'
import subprocess, json, os
try:
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        policy = json.loads(result.stdout)
        if policy.get("isEnabled", False):
            print(f"\033[0;32m[PASS]\033[0m IAM-01: Security Defaults are ENABLED in Entra ID")
        else:
            print(f"\033[1;33m[WARN]\033[0m IAM-01: Security Defaults are DISABLED — verify Conditional Access policies compensate")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-01: Unable to query Security Defaults (may require Graph API permissions)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-01: Could not check Security Defaults: {e}")
PYEOF

log "IAM-02: Checking for excessive Global Administrators (CIS 6.26)"
python3 - <<'PYEOF'
import subprocess, json
try:
    # Global Administrator role template ID
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members?$select=displayName,userPrincipalName,accountEnabled"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        data = json.loads(result.stdout)
        members = data.get("value", [])
        active = [m for m in members if m.get("accountEnabled", True)]
        count = len(active)
        if count < 2:
            print(f"\033[0;31m[FAIL]\033[0m IAM-02: Only {count} Global Admin(s) — need at least 2 for break-glass")
        elif count <= 4:
            print(f"\033[0;32m[PASS]\033[0m IAM-02: {count} Global Administrator(s) (recommended: 2-4)")
        else:
            print(f"\033[0;31m[FAIL]\033[0m IAM-02: {count} Global Administrator(s) — CIS recommends fewer than 5")
        for m in active:
            print(f"         -> {m.get('displayName','?')} ({m.get('userPrincipalName','?')})")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-02: Unable to enumerate Global Admins (requires Directory.Read.All)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-02: Could not check Global Admins: {e}")
PYEOF

log "IAM-03: Checking guest user access restrictions (CIS 6.15)"
python3 - <<'PYEOF'
import subprocess, json
try:
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        policy = json.loads(result.stdout)
        guest_access = policy.get("guestUserRoleId", "")
        # 2af84b1e = restricted, 10dae51f = same as members, a0b1b346 = most restricted
        if guest_access == "2af84b1e-214e-495b-83cb-2de06d62b069":
            print(f"\033[0;32m[PASS]\033[0m IAM-03: Guest user access is RESTRICTED (limited properties)")
        elif guest_access == "a0b1b346-4d3e-4e8b-98f8-753987be4970":
            print(f"\033[0;32m[PASS]\033[0m IAM-03: Guest user access is MOST RESTRICTED")
        elif guest_access == "10dae51f-b6af-4016-8d66-8c2a99b929b3":
            print(f"\033[0;31m[FAIL]\033[0m IAM-03: Guest users have SAME access as members — restrict immediately")
        else:
            print(f"\033[1;33m[WARN]\033[0m IAM-03: Guest access role ID: {guest_access} — verify configuration")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-03: Unable to query authorization policy")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-03: Could not check guest access: {e}")
PYEOF

log "IAM-04: Checking user consent for applications (CIS 6.12)"
python3 - <<'PYEOF'
import subprocess, json
try:
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        policy = json.loads(result.stdout)
        consent = policy.get("defaultUserRolePermissions", {}).get("permissionGrantPoliciesAssigned", [])
        if not consent or consent == []:
            print(f"\033[0;32m[PASS]\033[0m IAM-04: User consent for applications is set to 'Do not allow'")
        elif "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in consent:
            print(f"\033[0;31m[FAIL]\033[0m IAM-04: Users CAN consent to apps — set to 'Do not allow' (CIS 6.12)")
        else:
            print(f"\033[1;33m[WARN]\033[0m IAM-04: Consent policy: {consent} — review configuration")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-04: Unable to query consent policy")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-04: Could not check consent policy: {e}")
PYEOF

log "IAM-05: Checking if users can register applications (CIS 6.14)"
python3 - <<'PYEOF'
import subprocess, json
try:
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        policy = json.loads(result.stdout)
        can_register = policy.get("defaultUserRolePermissions", {}).get("allowedToCreateApps", True)
        if not can_register:
            print(f"\033[0;32m[PASS]\033[0m IAM-05: Users CANNOT register applications (CIS 6.14)")
        else:
            print(f"\033[0;31m[FAIL]\033[0m IAM-05: Users CAN register applications — set to 'No' (CIS 6.14)")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-05: Unable to query app registration policy")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-05: Could not check app registration setting: {e}")
PYEOF

log "IAM-06: Checking for custom subscription administrator roles (CIS 6.23)"
python3 - <<'PYEOF'
import subprocess, json, os
try:
    result = subprocess.run(
        ["az", "role", "definition", "list", "--custom-role-only", "true", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        roles = json.loads(result.stdout)
        sub_admin_roles = []
        for r in roles:
            perms = r.get("permissions", [])
            for p in perms:
                actions = p.get("actions", [])
                if "*" in actions or "*/write" in actions:
                    sub_admin_roles.append(r.get("roleName", "unknown"))
                    break
        if sub_admin_roles:
            print(f"\033[0;31m[FAIL]\033[0m IAM-06: {len(sub_admin_roles)} custom role(s) with subscription admin-level access (CIS 6.23)")
            for name in sub_admin_roles:
                print(f"         -> {name}")
        else:
            print(f"\033[0;32m[PASS]\033[0m IAM-06: No custom subscription administrator roles found")
        with open(os.environ.get("OUTPUT_DIR",".") + "/custom_roles.json", "w") as f:
            json.dump(roles, f, indent=2)
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-06: Unable to list custom roles")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-06: Could not check custom roles: {e}")
PYEOF

log "IAM-07: Checking password reset requirements (CIS 6.5)"
python3 - <<'PYEOF'
import subprocess, json
try:
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        print(f"\033[0;32m[PASS]\033[0m IAM-07: Authentication methods policy retrieved — review SSPR settings manually")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-07: Unable to query authentication methods policy (requires Policy.Read.All)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-07: Could not check password reset config: {e}")
PYEOF

log "IAM-08: Checking restrict non-admin tenant creation (CIS 6.4)"
python3 - <<'PYEOF'
import subprocess, json
try:
    result = subprocess.run(
        ["az", "rest", "--method", "GET",
         "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        policy = json.loads(result.stdout)
        can_create = policy.get("defaultUserRolePermissions", {}).get("allowedToCreateTenants", True)
        if not can_create:
            print(f"\033[0;32m[PASS]\033[0m IAM-08: Non-admin users CANNOT create tenants (CIS 6.4)")
        else:
            print(f"\033[0;31m[FAIL]\033[0m IAM-08: Non-admin users CAN create tenants — restrict this (CIS 6.4)")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-08: Unable to query tenant creation policy")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-08: Could not check tenant creation: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: STORAGE ACCOUNTS (CIS 2.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 2: STORAGE ACCOUNTS ══${NC}"

log "Retrieving storage accounts..."
az storage account list --output json > "$OUTPUT_DIR/storage_accounts.json" 2>/dev/null

log "STG-01/02/03/04: Storage account security checks (CIS 2.1/2.2)"
python3 - <<'PYEOF'
import json, os

output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    with open(f"{output_dir}/storage_accounts.json") as f:
        accounts = json.load(f)
except:
    accounts = []
    print(f"\033[1;33m[WARN]\033[0m STG: No storage accounts found or unable to list")

if not accounts:
    print(f"\033[0;34m[INFO]\033[0m STG: No storage accounts in this subscription")
else:
    for sa in accounts:
        name = sa.get("name", "unknown")
        rg = sa.get("resourceGroup", "unknown")

        # STG-01: HTTPS only (CIS 2.1)
        https_only = sa.get("enableHttpsTrafficOnly", False) or sa.get("supportsHttpsTrafficOnly", False)
        if https_only:
            print(f"\033[0;32m[PASS]\033[0m STG-01: {name} — HTTPS-only traffic enforced")
        else:
            print(f"\033[0;31m[FAIL]\033[0m STG-01: {name} — HTTPS-only NOT enforced (CIS 2.1)")

        # STG-02: Default network access rule (CIS 2.2.1.2)
        net_rules = sa.get("networkRuleSet", {})
        default_action = net_rules.get("defaultAction", "Allow")
        if default_action == "Deny":
            print(f"\033[0;32m[PASS]\033[0m STG-02: {name} — Default network rule is DENY")
        else:
            print(f"\033[0;31m[FAIL]\033[0m STG-02: {name} — Default network rule is ALLOW — set to Deny (CIS 2.2.1.2)")

        # STG-03: Minimum TLS version
        min_tls = sa.get("minimumTlsVersion", "TLS1_0")
        if min_tls in ("TLS1_2", "TLS1_3"):
            print(f"\033[0;32m[PASS]\033[0m STG-03: {name} — Minimum TLS version: {min_tls}")
        else:
            print(f"\033[0;31m[FAIL]\033[0m STG-03: {name} — Minimum TLS is {min_tls} — set to TLS1_2 or higher")

        # STG-04: Public blob access
        allow_blob_public = sa.get("allowBlobPublicAccess", True)
        if not allow_blob_public:
            print(f"\033[0;32m[PASS]\033[0m STG-04: {name} — Public blob access DISABLED")
        else:
            print(f"\033[0;31m[FAIL]\033[0m STG-04: {name} — Public blob access ENABLED — disable it")

        # STG-05: Infrastructure encryption (double encryption)
        infra_encrypt = sa.get("encryption", {}).get("requireInfrastructureEncryption", False)
        if infra_encrypt:
            print(f"\033[0;32m[PASS]\033[0m STG-05: {name} — Infrastructure encryption (double) ENABLED")
        else:
            print(f"\033[1;33m[WARN]\033[0m STG-05: {name} — Infrastructure encryption NOT enabled (recommended for sensitive data)")

        # STG-06: Shared key access
        allow_shared_key = sa.get("allowSharedKeyAccess", True)
        if not allow_shared_key:
            print(f"\033[0;32m[PASS]\033[0m STG-06: {name} — Shared Key access DISABLED (Entra ID auth enforced)")
        else:
            print(f"\033[1;33m[WARN]\033[0m STG-06: {name} — Shared Key access enabled — consider disabling for Entra-only auth")

        print("")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: NETWORKING (CIS 8.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 3: NETWORKING ══${NC}"

log "NET-01/02/03/04: Network Security Group checks (CIS 8.1-8.4)"
python3 - <<'PYEOF'
import subprocess, json, os

output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    result = subprocess.run(
        ["az", "network", "nsg", "list", "--output", "json"],
        capture_output=True, text=True, timeout=60
    )
    nsgs = json.loads(result.stdout) if result.returncode == 0 else []
except:
    nsgs = []

if not nsgs:
    print(f"\033[0;34m[INFO]\033[0m NET: No Network Security Groups found")
else:
    with open(f"{output_dir}/nsgs.json", "w") as f:
        json.dump(nsgs, f, indent=2)

    risky_ports = {
        "3389": ("RDP", "NET-01", "CIS 8.1"),
        "22": ("SSH", "NET-02", "CIS 8.2"),
        "53": ("DNS/UDP", "NET-03", "CIS 8.3"),
        "80": ("HTTP", "NET-04", "CIS 8.4"),
        "443": ("HTTPS", "NET-04", "CIS 8.4"),
    }

    issues_found = False
    for nsg in nsgs:
        nsg_name = nsg.get("name", "unknown")
        rules = nsg.get("securityRules", [])

        for rule in rules:
            if rule.get("access", "").lower() != "allow":
                continue
            if rule.get("direction", "").lower() != "inbound":
                continue

            src = rule.get("sourceAddressPrefix", "")
            dst_port = str(rule.get("destinationPortRange", ""))
            dst_ports = rule.get("destinationPortRanges", [])
            all_ports = [dst_port] + dst_ports

            if src not in ("*", "0.0.0.0/0", "Internet", "Any"):
                continue

            for port in all_ports:
                if port == "*":
                    print(f"\033[0;31m[FAIL]\033[0m NET-01: NSG '{nsg_name}' rule '{rule.get('name')}' allows ALL ports from Internet")
                    issues_found = True
                elif port in risky_ports:
                    svc, check_id, cis_ref = risky_ports[port]
                    print(f"\033[0;31m[FAIL]\033[0m {check_id}: NSG '{nsg_name}' allows {svc} ({port}) from Internet ({cis_ref})")
                    issues_found = True
                elif "-" in port:
                    try:
                        low, high = port.split("-")
                        for rp, (svc, check_id, cis_ref) in risky_ports.items():
                            if int(low) <= int(rp) <= int(high):
                                print(f"\033[0;31m[FAIL]\033[0m {check_id}: NSG '{nsg_name}' range {port} includes {svc} from Internet ({cis_ref})")
                                issues_found = True
                    except:
                        pass

    if not issues_found:
        print(f"\033[0;32m[PASS]\033[0m NET-01/02/03/04: No Internet-exposed risky ports found in NSGs")

log_msg = f"Scanned {len(nsgs)} NSG(s)"
print(f"\033[0;34m[INFO]\033[0m {log_msg}")
PYEOF

log "NET-05: Checking Network Watcher status (CIS 8.6)"
python3 - <<'PYEOF'
import subprocess, json
try:
    result = subprocess.run(
        ["az", "network", "watcher", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    watchers = json.loads(result.stdout) if result.returncode == 0 else []

    locations_result = subprocess.run(
        ["az", "account", "list-locations", "--query", "[?metadata.regionType=='Physical'].name", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    all_locations = json.loads(locations_result.stdout) if locations_result.returncode == 0 else []

    watcher_locations = {w.get("location", "").lower() for w in watchers if w.get("provisioningState") == "Succeeded"}

    # Check against locations where resources are deployed
    rg_result = subprocess.run(
        ["az", "group", "list", "--query", "[].location", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    used_locations = set(json.loads(rg_result.stdout)) if rg_result.returncode == 0 else set()

    missing = used_locations - watcher_locations
    if not missing:
        print(f"\033[0;32m[PASS]\033[0m NET-05: Network Watcher enabled in all {len(used_locations)} active region(s) (CIS 8.6)")
    else:
        print(f"\033[0;31m[FAIL]\033[0m NET-05: Network Watcher MISSING in {len(missing)} region(s) (CIS 8.6):")
        for loc in sorted(missing):
            print(f"         -> {loc}")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m NET-05: Could not check Network Watcher: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: LOGGING & MONITORING (CIS 7.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 4: LOGGING & MONITORING ══${NC}"

log "LOG-01: Checking Diagnostic Setting for Activity Logs (CIS 7.1.1.1)"
python3 - <<'PYEOF'
import subprocess, json, os

output_dir = os.environ.get("OUTPUT_DIR", ".")
sub_id = os.popen("az account show --query id -o tsv").read().strip()
try:
    result = subprocess.run(
        ["az", "monitor", "diagnostic-settings", "subscription", "list",
         "--subscription", sub_id, "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    settings = json.loads(result.stdout).get("value", []) if result.returncode == 0 else []

    with open(f"{output_dir}/diagnostic_settings.json", "w") as f:
        json.dump(settings, f, indent=2)

    if settings:
        print(f"\033[0;32m[PASS]\033[0m LOG-01: {len(settings)} Diagnostic Setting(s) configured for Activity Logs (CIS 7.1.1.1)")
        for ds in settings:
            name = ds.get("name", "unknown")
            workspace = ds.get("workspaceId", "none")
            storage = ds.get("storageAccountId", "none")
            print(f"         -> {name} (workspace: {'yes' if workspace else 'no'}, storage: {'yes' if storage else 'no'})")
    else:
        print(f"\033[0;31m[FAIL]\033[0m LOG-01: NO Diagnostic Settings for Activity Logs (CIS 7.1.1.1)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m LOG-01: Could not check diagnostic settings: {e}")
PYEOF

log "LOG-02: Checking Activity Log Alerts (CIS 7.1.2.x)"
python3 - <<'PYEOF'
import subprocess, json

required_alerts = {
    "Microsoft.Authorization/policyAssignments/write": ("LOG-02a", "CIS 7.1.2.1", "Create Policy Assignment"),
    "Microsoft.Authorization/policyAssignments/delete": ("LOG-02b", "CIS 7.1.2.2", "Delete Policy Assignment"),
    "Microsoft.Network/networkSecurityGroups/write": ("LOG-02c", "CIS 7.1.2.3", "Create/Update NSG"),
    "Microsoft.Network/networkSecurityGroups/delete": ("LOG-02d", "CIS 7.1.2.4", "Delete NSG"),
    "Microsoft.Security/securitySolutions/write": ("LOG-02e", "CIS 7.1.2.5", "Create/Update Security Solution"),
    "Microsoft.Security/securitySolutions/delete": ("LOG-02f", "CIS 7.1.2.6", "Delete Security Solution"),
    "Microsoft.Sql/servers/firewallRules/write": ("LOG-02g", "CIS 7.1.2.7", "Create/Update SQL FW Rule"),
    "Microsoft.Sql/servers/firewallRules/delete": ("LOG-02h", "CIS 7.1.2.8", "Delete SQL FW Rule"),
    "Microsoft.Network/publicIPAddresses/write": ("LOG-02i", "CIS 7.1.2.9", "Create/Update Public IP"),
    "Microsoft.Network/publicIPAddresses/delete": ("LOG-02j", "CIS 7.1.2.10", "Delete Public IP"),
}

try:
    result = subprocess.run(
        ["az", "monitor", "activity-log", "alert", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    alerts = json.loads(result.stdout) if result.returncode == 0 else []

    configured_ops = set()
    for alert in alerts:
        if not alert.get("enabled", False):
            continue
        condition = alert.get("condition", {})
        all_of = condition.get("allOf", [])
        for cond in all_of:
            if cond.get("field") == "operationName":
                configured_ops.add(cond.get("equals", ""))

    for op, (check_id, cis_ref, desc) in required_alerts.items():
        if op in configured_ops:
            print(f"\033[0;32m[PASS]\033[0m {check_id}: Activity Log Alert exists for '{desc}' ({cis_ref})")
        else:
            print(f"\033[0;31m[FAIL]\033[0m {check_id}: No Activity Log Alert for '{desc}' ({cis_ref})")

except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m LOG-02: Could not check activity log alerts: {e}")
PYEOF

log "LOG-03: Checking Key Vault logging (CIS 7.1.1.4)"
python3 - <<'PYEOF'
import subprocess, json

try:
    kv_result = subprocess.run(
        ["az", "keyvault", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    vaults = json.loads(kv_result.stdout) if kv_result.returncode == 0 else []

    if not vaults:
        print(f"\033[0;34m[INFO]\033[0m LOG-03: No Key Vaults found in this subscription")
    else:
        for vault in vaults:
            name = vault.get("name", "unknown")
            vault_id = vault.get("id", "")
            ds_result = subprocess.run(
                ["az", "monitor", "diagnostic-settings", "list",
                 "--resource", vault_id, "--output", "json"],
                capture_output=True, text=True, timeout=30
            )
            ds_list = json.loads(ds_result.stdout).get("value", []) if ds_result.returncode == 0 else []

            has_audit_log = False
            for ds in ds_list:
                logs = ds.get("logs", [])
                for log_entry in logs:
                    cat = log_entry.get("category", "")
                    enabled = log_entry.get("enabled", False)
                    if cat == "AuditEvent" and enabled:
                        has_audit_log = True

            if has_audit_log:
                print(f"\033[0;32m[PASS]\033[0m LOG-03: Key Vault '{name}' — AuditEvent logging ENABLED (CIS 7.1.1.4)")
            else:
                print(f"\033[0;31m[FAIL]\033[0m LOG-03: Key Vault '{name}' — AuditEvent logging NOT configured (CIS 7.1.1.4)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m LOG-03: Could not check Key Vault logging: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: KEY VAULT (CIS 2.x / 9.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 5: KEY VAULT ══${NC}"

log "KV-01/02/03: Key Vault configuration checks"
python3 - <<'PYEOF'
import subprocess, json, os
from datetime import datetime, timezone

output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    result = subprocess.run(
        ["az", "keyvault", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    vaults = json.loads(result.stdout) if result.returncode == 0 else []

    if not vaults:
        print(f"\033[0;34m[INFO]\033[0m KV: No Key Vaults found")
    else:
        with open(f"{output_dir}/keyvaults.json", "w") as f:
            json.dump(vaults, f, indent=2)

        for vault in vaults:
            name = vault.get("name", "unknown")
            props = vault.get("properties", vault)

            # KV-01: Soft delete enabled
            soft_delete = props.get("enableSoftDelete", False)
            if soft_delete:
                print(f"\033[0;32m[PASS]\033[0m KV-01: '{name}' — Soft delete ENABLED")
            else:
                print(f"\033[0;31m[FAIL]\033[0m KV-01: '{name}' — Soft delete NOT enabled")

            # KV-02: Purge protection
            purge_protect = props.get("enablePurgeProtection", False)
            if purge_protect:
                print(f"\033[0;32m[PASS]\033[0m KV-02: '{name}' — Purge protection ENABLED")
            else:
                print(f"\033[0;31m[FAIL]\033[0m KV-02: '{name}' — Purge protection NOT enabled — enable for production vaults")

            # KV-03: RBAC authorization (vs access policies)
            rbac = props.get("enableRbacAuthorization", False)
            if rbac:
                print(f"\033[0;32m[PASS]\033[0m KV-03: '{name}' — RBAC authorization ENABLED")
            else:
                print(f"\033[1;33m[WARN]\033[0m KV-03: '{name}' — Using access policies instead of RBAC — consider migrating")

            # KV-04: Network restrictions
            net_acls = props.get("networkAcls", {})
            default_action = net_acls.get("defaultAction", "Allow")
            if default_action == "Deny":
                print(f"\033[0;32m[PASS]\033[0m KV-04: '{name}' — Network default action is DENY")
            else:
                print(f"\033[0;31m[FAIL]\033[0m KV-04: '{name}' — Network default action is ALLOW — restrict access")

            print("")

except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m KV: Could not check Key Vaults: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: COMPUTE / VIRTUAL MACHINES
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 6: COMPUTE / VIRTUAL MACHINES ══${NC}"

log "VM-01/02/03/04: Virtual Machine security checks"
python3 - <<'PYEOF'
import subprocess, json, os

output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    result = subprocess.run(
        ["az", "vm", "list", "--show-details", "--output", "json"],
        capture_output=True, text=True, timeout=120
    )
    vms = json.loads(result.stdout) if result.returncode == 0 else []

    if not vms:
        print(f"\033[0;34m[INFO]\033[0m VM: No Virtual Machines found in this subscription")
    else:
        with open(f"{output_dir}/virtual_machines.json", "w") as f:
            json.dump(vms, f, indent=2)

        for vm in vms:
            name = vm.get("name", "unknown")
            rg = vm.get("resourceGroup", "unknown")

            # VM-01: OS disk encryption
            os_disk = vm.get("storageProfile", {}).get("osDisk", {})
            encryption = os_disk.get("encryptionSettings", {})
            managed = os_disk.get("managedDisk", {})
            disk_encrypt = managed.get("diskEncryptionSet", None)
            sse_type = managed.get("storageAccountType", "")

            if encryption.get("enabled") or disk_encrypt:
                print(f"\033[0;32m[PASS]\033[0m VM-01: '{name}' — OS disk encryption ENABLED")
            else:
                print(f"\033[1;33m[WARN]\033[0m VM-01: '{name}' — OS disk using platform-managed encryption only (consider CMK)")

            # VM-02: Public IP check
            public_ips = vm.get("publicIps", "")
            if public_ips:
                print(f"\033[1;33m[WARN]\033[0m VM-02: '{name}' — Has PUBLIC IP: {public_ips}")
            else:
                print(f"\033[0;32m[PASS]\033[0m VM-02: '{name}' — No public IP assigned")

            # VM-03: Managed identity
            identity = vm.get("identity", {})
            identity_type = identity.get("type", "None") if identity else "None"
            if identity_type != "None" and identity_type is not None:
                print(f"\033[0;32m[PASS]\033[0m VM-03: '{name}' — Managed identity: {identity_type}")
            else:
                print(f"\033[1;33m[WARN]\033[0m VM-03: '{name}' — No managed identity — consider enabling for secretless auth")

            # VM-04: Extensions audit
            extensions = vm.get("resources", [])
            ext_names = [e.get("id", "").split("/")[-1] for e in (extensions or [])]
            if ext_names:
                print(f"\033[0;34m[INFO]\033[0m VM-04: '{name}' — Extensions: {', '.join(ext_names)}")

            print("")

    print(f"\033[0;34m[INFO]\033[0m Scanned {len(vms)} VM(s)")

except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m VM: Could not check Virtual Machines: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: APP SERVICE / WEB APPS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 7: APP SERVICE / WEB APPS ══${NC}"

log "APP-01/02/03/04: App Service security checks"
python3 - <<'PYEOF'
import subprocess, json, os

output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    result = subprocess.run(
        ["az", "webapp", "list", "--output", "json"],
        capture_output=True, text=True, timeout=60
    )
    apps = json.loads(result.stdout) if result.returncode == 0 else []

    if not apps:
        print(f"\033[0;34m[INFO]\033[0m APP: No App Service web apps found")
    else:
        with open(f"{output_dir}/app_services.json", "w") as f:
            json.dump(apps, f, indent=2)

        for app in apps:
            name = app.get("name", "unknown")
            rg = app.get("resourceGroup", "unknown")

            # APP-01: HTTPS only
            https_only = app.get("httpsOnly", False)
            if https_only:
                print(f"\033[0;32m[PASS]\033[0m APP-01: '{name}' — HTTPS-only ENABLED")
            else:
                print(f"\033[0;31m[FAIL]\033[0m APP-01: '{name}' — HTTPS-only NOT enforced")

            # Fetch detailed config
            try:
                cfg_result = subprocess.run(
                    ["az", "webapp", "show", "--name", name, "--resource-group", rg, "--output", "json"],
                    capture_output=True, text=True, timeout=30
                )
                config = json.loads(cfg_result.stdout) if cfg_result.returncode == 0 else {}
            except:
                config = {}

            site_config = config.get("siteConfig", {})

            # APP-02: Minimum TLS version
            min_tls = site_config.get("minTlsVersion", "1.0")
            if min_tls in ("1.2", "1.3"):
                print(f"\033[0;32m[PASS]\033[0m APP-02: '{name}' — Minimum TLS: {min_tls}")
            else:
                print(f"\033[0;31m[FAIL]\033[0m APP-02: '{name}' — Minimum TLS is {min_tls} — set to 1.2+")

            # APP-03: Managed identity
            identity = config.get("identity", {})
            id_type = identity.get("type", "None") if identity else "None"
            if id_type and id_type != "None":
                print(f"\033[0;32m[PASS]\033[0m APP-03: '{name}' — Managed identity: {id_type}")
            else:
                print(f"\033[1;33m[WARN]\033[0m APP-03: '{name}' — No managed identity configured")

            # APP-04: FTP state
            ftp_state = site_config.get("ftpsState", "AllAllowed")
            if ftp_state in ("Disabled", "FtpsOnly"):
                print(f"\033[0;32m[PASS]\033[0m APP-04: '{name}' — FTP state: {ftp_state}")
            else:
                print(f"\033[0;31m[FAIL]\033[0m APP-04: '{name}' — FTP state is {ftp_state} — disable or set to FTPS-only")

            # APP-05: HTTP logging (CIS 7.1.1.6)
            http_logs = site_config.get("httpLoggingEnabled", False)
            if http_logs:
                print(f"\033[0;32m[PASS]\033[0m APP-05: '{name}' — HTTP logging ENABLED (CIS 7.1.1.6)")
            else:
                print(f"\033[0;31m[FAIL]\033[0m APP-05: '{name}' — HTTP logging NOT enabled (CIS 7.1.1.6)")

            print("")

    print(f"\033[0;34m[INFO]\033[0m Scanned {len(apps)} App Service(s)")

except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m APP: Could not check App Services: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: DATABASE SERVICES
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 8: DATABASE SERVICES ══${NC}"

log "DB-01/02/03/04: Azure SQL Database security checks"
python3 - <<'PYEOF'
import subprocess, json, os

output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    result = subprocess.run(
        ["az", "sql", "server", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    servers = json.loads(result.stdout) if result.returncode == 0 else []

    if not servers:
        print(f"\033[0;34m[INFO]\033[0m DB: No Azure SQL Servers found")
    else:
        with open(f"{output_dir}/sql_servers.json", "w") as f:
            json.dump(servers, f, indent=2)

        for server in servers:
            name = server.get("name", "unknown")
            rg = server.get("resourceGroup", "unknown")

            # DB-01: Auditing enabled
            try:
                audit_result = subprocess.run(
                    ["az", "sql", "server", "audit-policy", "show",
                     "--name", name, "--resource-group", rg, "--output", "json"],
                    capture_output=True, text=True, timeout=30
                )
                audit = json.loads(audit_result.stdout) if audit_result.returncode == 0 else {}
                state = audit.get("state", "Disabled")
                if state == "Enabled":
                    print(f"\033[0;32m[PASS]\033[0m DB-01: SQL Server '{name}' — Auditing ENABLED")
                else:
                    print(f"\033[0;31m[FAIL]\033[0m DB-01: SQL Server '{name}' — Auditing NOT enabled")
            except:
                print(f"\033[1;33m[WARN]\033[0m DB-01: Could not check auditing for '{name}'")

            # DB-02: TDE (Transparent Data Encryption) — check databases
            try:
                dbs_result = subprocess.run(
                    ["az", "sql", "db", "list", "--server", name, "--resource-group", rg,
                     "--query", "[?name!='master'].name", "--output", "json"],
                    capture_output=True, text=True, timeout=30
                )
                dbs = json.loads(dbs_result.stdout) if dbs_result.returncode == 0 else []
                for db_name in dbs:
                    tde_result = subprocess.run(
                        ["az", "sql", "db", "tde", "show", "--server", name,
                         "--resource-group", rg, "--database", db_name, "--output", "json"],
                        capture_output=True, text=True, timeout=30
                    )
                    tde = json.loads(tde_result.stdout) if tde_result.returncode == 0 else {}
                    tde_state = tde.get("state", "Disabled")
                    if tde_state == "Enabled":
                        print(f"\033[0;32m[PASS]\033[0m DB-02: '{name}/{db_name}' — TDE ENABLED")
                    else:
                        print(f"\033[0;31m[FAIL]\033[0m DB-02: '{name}/{db_name}' — TDE NOT enabled")
            except:
                print(f"\033[1;33m[WARN]\033[0m DB-02: Could not check TDE for '{name}'")

            # DB-03: Public network access
            public_access = server.get("publicNetworkAccess", "Enabled")
            if public_access == "Disabled":
                print(f"\033[0;32m[PASS]\033[0m DB-03: SQL Server '{name}' — Public network access DISABLED")
            else:
                print(f"\033[1;33m[WARN]\033[0m DB-03: SQL Server '{name}' — Public network access ENABLED — restrict with firewall rules")

            # DB-04: Entra-only authentication
            try:
                admin_result = subprocess.run(
                    ["az", "sql", "server", "ad-admin", "list",
                     "--server", name, "--resource-group", rg, "--output", "json"],
                    capture_output=True, text=True, timeout=30
                )
                admins = json.loads(admin_result.stdout) if admin_result.returncode == 0 else []
                if admins:
                    print(f"\033[0;32m[PASS]\033[0m DB-04: SQL Server '{name}' — Entra ID admin configured")
                else:
                    print(f"\033[0;31m[FAIL]\033[0m DB-04: SQL Server '{name}' — No Entra ID admin set")
            except:
                print(f"\033[1;33m[WARN]\033[0m DB-04: Could not check Entra admin for '{name}'")

            print("")

except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m DB: Could not check SQL Servers: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "======================================================================"
echo -e " AUDIT COMPLETE"
echo -e " ${GREEN}PASS : $PASS${NC}"
echo -e " ${RED}FAIL : $FAIL${NC}"
echo -e " ${YELLOW}WARN : $WARN${NC}"
echo -e " Total: $((PASS + FAIL + WARN))"
echo " Evidence: $OUTPUT_DIR/"
echo "======================================================================"

# Write manifest
{
    echo "Azure Security Audit — Evidence Manifest"
    echo "========================================="
    echo "Date       : $(date)"
    echo "Subscription: $SUB_NAME ($SUB_ID)"
    echo "Tenant     : $TENANT_ID"
    echo "Results    : PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
    echo ""
    echo "Evidence files:"
    ls -la "$OUTPUT_DIR/" 2>/dev/null | tail -n +4
} > "$OUTPUT_DIR/AUDIT_MANIFEST.txt"

# Exit code: 1 if any FAIL, 0 otherwise
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
