#!/usr/bin/env bash
# ============================================================================
# Azure Cloud Security Audit — Enhanced Testing Script
# Aligned to: CIS Microsoft Azure Foundations Benchmark v4.0.0
# Requirements: Azure CLI 2.50+, Python 3.8+, logged-in az session
# Usage: bash azure_security_audit_enhanced.sh [--subscription <id>]
# Sections: 16 sections, 70+ checks
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
export OUTPUT_DIR SUB_ID TENANT_ID

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

log()  { echo -e "${BLUE}[*]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

echo "======================================================================"
echo " Azure Cloud Security Audit — Enhanced Script (16 Sections)"
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

log "IAM-01: Security Defaults status (CIS 6.1.1)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        p = json.loads(r.stdout)
        if p.get("isEnabled"):
            print(f"\033[0;32m[PASS]\033[0m IAM-01: Security Defaults ENABLED (CIS 6.1.1)")
        else:
            print(f"\033[1;33m[WARN]\033[0m IAM-01: Security Defaults DISABLED — verify Conditional Access compensates (CIS 6.1.1)")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-01: Cannot query Security Defaults (needs Graph permissions)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-01: {e}")
PYEOF

log "IAM-02: Global Administrator count (CIS 6.26)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members?$select=displayName,userPrincipalName,accountEnabled"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        members = json.loads(r.stdout).get("value", [])
        active = [m for m in members if m.get("accountEnabled", True)]
        c = len(active)
        if c < 2: print(f"\033[0;31m[FAIL]\033[0m IAM-02: Only {c} Global Admin(s) — need >=2 break-glass (CIS 6.26)")
        elif c <= 4: print(f"\033[0;32m[PASS]\033[0m IAM-02: {c} Global Admin(s) — within recommended 2-4 (CIS 6.26)")
        else: print(f"\033[0;31m[FAIL]\033[0m IAM-02: {c} Global Admin(s) — CIS recommends <5 (CIS 6.26)")
        for m in active: print(f"         -> {m.get('displayName','?')} ({m.get('userPrincipalName','?')})")
    else:
        print(f"\033[1;33m[WARN]\033[0m IAM-02: Cannot enumerate Global Admins (needs Directory.Read.All)")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m IAM-02: {e}")
PYEOF

log "IAM-03: Guest user access restrictions (CIS 6.15)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/policies/authorizationPolicy"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        p = json.loads(r.stdout)
        gid = p.get("guestUserRoleId","")
        if gid in ("2af84b1e-214e-495b-83cb-2de06d62b069","a0b1b346-4d3e-4e8b-98f8-753987be4970"):
            print(f"\033[0;32m[PASS]\033[0m IAM-03: Guest access RESTRICTED (CIS 6.15)")
        elif gid == "10dae51f-b6af-4016-8d66-8c2a99b929b3":
            print(f"\033[0;31m[FAIL]\033[0m IAM-03: Guests have SAME access as members (CIS 6.15)")
        else:
            print(f"\033[1;33m[WARN]\033[0m IAM-03: Guest role ID: {gid}")
    else: print(f"\033[1;33m[WARN]\033[0m IAM-03: Cannot query authorization policy")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m IAM-03: {e}")
PYEOF

log "IAM-04: User consent for applications (CIS 6.12)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/policies/authorizationPolicy"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        p = json.loads(r.stdout)
        c = p.get("defaultUserRolePermissions",{}).get("permissionGrantPoliciesAssigned",[])
        if not c: print(f"\033[0;32m[PASS]\033[0m IAM-04: User consent set to 'Do not allow' (CIS 6.12)")
        elif "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in c:
            print(f"\033[0;31m[FAIL]\033[0m IAM-04: Users CAN consent to apps (CIS 6.12)")
        elif "ManagePermissionGrantsForSelf.microsoft-user-default-recommended" in c:
            print(f"\033[1;33m[WARN]\033[0m IAM-04: Users can consent to verified publishers only (CIS 6.13 L2)")
        else: print(f"\033[1;33m[WARN]\033[0m IAM-04: Consent policy: {c}")
    else: print(f"\033[1;33m[WARN]\033[0m IAM-04: Cannot query consent policy")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m IAM-04: {e}")
PYEOF

log "IAM-05: Users can register applications (CIS 6.14)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/policies/authorizationPolicy"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        p = json.loads(r.stdout)
        if not p.get("defaultUserRolePermissions",{}).get("allowedToCreateApps",True):
            print(f"\033[0;32m[PASS]\033[0m IAM-05: Users CANNOT register applications (CIS 6.14)")
        else: print(f"\033[0;31m[FAIL]\033[0m IAM-05: Users CAN register applications (CIS 6.14)")
    else: print(f"\033[1;33m[WARN]\033[0m IAM-05: Cannot query policy")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m IAM-05: {e}")
PYEOF

log "IAM-06: Custom subscription admin roles (CIS 6.23)"
python3 - <<'PYEOF'
import subprocess, json, os
try:
    r = subprocess.run(["az","role","definition","list","--custom-role-only","true","--output","json"], capture_output=True, text=True, timeout=30)
    roles = json.loads(r.stdout) if r.returncode == 0 else []
    bad = [ro.get("roleName","?") for ro in roles if any("*" in (p.get("actions",[]) or []) for p in ro.get("permissions",[]))]
    if bad:
        print(f"\033[0;31m[FAIL]\033[0m IAM-06: {len(bad)} custom role(s) with wildcard actions (CIS 6.23)")
        for n in bad: print(f"         -> {n}")
    else: print(f"\033[0;32m[PASS]\033[0m IAM-06: No custom subscription admin roles (CIS 6.23)")
    with open(os.environ.get("OUTPUT_DIR",".")+"/custom_roles.json","w") as f: json.dump(roles,f,indent=2)
except Exception as e: print(f"\033[1;33m[WARN]\033[0m IAM-06: {e}")
PYEOF

log "IAM-07: Non-admin tenant creation (CIS 6.4)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/policies/authorizationPolicy"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        p = json.loads(r.stdout)
        if not p.get("defaultUserRolePermissions",{}).get("allowedToCreateTenants",True):
            print(f"\033[0;32m[PASS]\033[0m IAM-07: Non-admin tenant creation DISABLED (CIS 6.4)")
        else: print(f"\033[0;31m[FAIL]\033[0m IAM-07: Non-admin users CAN create tenants (CIS 6.4)")
    else: print(f"\033[1;33m[WARN]\033[0m IAM-07: Cannot query policy")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m IAM-07: {e}")
PYEOF

log "IAM-08: Guest invite restrictions (CIS 6.16)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/policies/authorizationPolicy"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        p = json.loads(r.stdout)
        invite = p.get("allowInvitesFrom","everyone")
        if invite in ("adminsAndGuestInviters","none"):
            print(f"\033[0;32m[PASS]\033[0m IAM-08: Guest invites restricted to '{invite}' (CIS 6.16)")
        else:
            print(f"\033[0;31m[FAIL]\033[0m IAM-08: Guest invites allowed from '{invite}' — restrict (CIS 6.16)")
    else: print(f"\033[1;33m[WARN]\033[0m IAM-08: Cannot query invite policy")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m IAM-08: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: STORAGE ACCOUNTS (CIS 2.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 2: STORAGE ACCOUNTS ══${NC}"

log "Retrieving storage accounts..."
az storage account list --output json > "$OUTPUT_DIR/storage_accounts.json" 2>/dev/null

log "STG-01 to STG-06: Storage account security checks"
python3 - <<'PYEOF'
import json, os
output_dir = os.environ.get("OUTPUT_DIR", ".")
try:
    with open(f"{output_dir}/storage_accounts.json") as f: accounts = json.load(f)
except: accounts = []

if not accounts:
    print(f"\033[0;34m[INFO]\033[0m STG: No storage accounts found")
else:
    for sa in accounts:
        n = sa.get("name","?")
        if sa.get("enableHttpsTrafficOnly",False) or sa.get("supportsHttpsTrafficOnly",False):
            print(f"\033[0;32m[PASS]\033[0m STG-01: {n} — HTTPS-only enforced")
        else: print(f"\033[0;31m[FAIL]\033[0m STG-01: {n} — HTTPS-only NOT enforced (CIS 2.1)")

        da = sa.get("networkRuleSet",{}).get("defaultAction","Allow")
        if da == "Deny": print(f"\033[0;32m[PASS]\033[0m STG-02: {n} — Network default DENY (CIS 2.2.1.2)")
        else: print(f"\033[0;31m[FAIL]\033[0m STG-02: {n} — Network default ALLOW (CIS 2.2.1.2)")

        tls = sa.get("minimumTlsVersion","TLS1_0")
        if tls in ("TLS1_2","TLS1_3"): print(f"\033[0;32m[PASS]\033[0m STG-03: {n} — TLS {tls}")
        else: print(f"\033[0;31m[FAIL]\033[0m STG-03: {n} — TLS {tls} — set to TLS1_2+")

        if not sa.get("allowBlobPublicAccess",True): print(f"\033[0;32m[PASS]\033[0m STG-04: {n} — Public blob DISABLED")
        else: print(f"\033[0;31m[FAIL]\033[0m STG-04: {n} — Public blob ENABLED")

        if sa.get("encryption",{}).get("requireInfrastructureEncryption",False):
            print(f"\033[0;32m[PASS]\033[0m STG-05: {n} — Infrastructure encryption ENABLED")
        else: print(f"\033[1;33m[WARN]\033[0m STG-05: {n} — No infrastructure encryption (CIS 2.1.1.1)")

        if not sa.get("allowSharedKeyAccess",True):
            print(f"\033[0;32m[PASS]\033[0m STG-06: {n} — Shared Key DISABLED")
        else: print(f"\033[1;33m[WARN]\033[0m STG-06: {n} — Shared Key enabled")
        print("")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: NETWORKING (CIS 8.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 3: NETWORKING ══${NC}"

log "NET-01/02/03/04: NSG risky port checks (CIS 8.1-8.4)"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
try:
    r = subprocess.run(["az","network","nsg","list","--output","json"], capture_output=True, text=True, timeout=60)
    nsgs = json.loads(r.stdout) if r.returncode == 0 else []
except: nsgs = []

if not nsgs: print(f"\033[0;34m[INFO]\033[0m NET: No NSGs found")
else:
    with open(f"{output_dir}/nsgs.json","w") as f: json.dump(nsgs,f,indent=2)
    risky = {"3389":("RDP","NET-01","8.1"),"22":("SSH","NET-02","8.2"),"53":("DNS","NET-03","8.3"),"80":("HTTP","NET-04","8.4"),"443":("HTTPS","NET-04","8.4")}
    found = False
    for nsg in nsgs:
        nn = nsg.get("name","?")
        for rule in nsg.get("securityRules",[]):
            if rule.get("access","").lower()!="allow" or rule.get("direction","").lower()!="inbound": continue
            src = rule.get("sourceAddressPrefix","")
            if src not in ("*","0.0.0.0/0","Internet","Any"): continue
            ports = [str(rule.get("destinationPortRange",""))] + rule.get("destinationPortRanges",[])
            for port in ports:
                if port == "*":
                    print(f"\033[0;31m[FAIL]\033[0m NET-01: NSG '{nn}' allows ALL ports from Internet"); found = True
                elif port in risky:
                    s,c,ref = risky[port]; print(f"\033[0;31m[FAIL]\033[0m {c}: NSG '{nn}' allows {s}/{port} from Internet (CIS {ref})"); found = True
                elif "-" in port:
                    try:
                        lo,hi = port.split("-")
                        for rp,(s,c,ref) in risky.items():
                            if int(lo)<=int(rp)<=int(hi): print(f"\033[0;31m[FAIL]\033[0m {c}: NSG '{nn}' range {port} includes {s} (CIS {ref})"); found = True
                    except: pass
    if not found: print(f"\033[0;32m[PASS]\033[0m NET-01/02/03/04: No Internet-exposed risky ports")
    print(f"\033[0;34m[INFO]\033[0m Scanned {len(nsgs)} NSG(s)")
PYEOF

log "NET-05: Network Watcher (CIS 8.6)"
python3 - <<'PYEOF'
import subprocess, json
try:
    wr = subprocess.run(["az","network","watcher","list","--output","json"], capture_output=True, text=True, timeout=30)
    watchers = json.loads(wr.stdout) if wr.returncode == 0 else []
    wlocs = {w.get("location","").lower() for w in watchers if w.get("provisioningState")=="Succeeded"}
    rr = subprocess.run(["az","group","list","--query","[].location","--output","json"], capture_output=True, text=True, timeout=30)
    used = set(json.loads(rr.stdout)) if rr.returncode == 0 else set()
    missing = used - wlocs
    if not missing: print(f"\033[0;32m[PASS]\033[0m NET-05: Network Watcher enabled in all {len(used)} active region(s) (CIS 8.6)")
    else:
        print(f"\033[0;31m[FAIL]\033[0m NET-05: Network Watcher missing in {len(missing)} region(s) (CIS 8.6)")
        for l in sorted(missing): print(f"         -> {l}")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m NET-05: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: LOGGING & MONITORING (CIS 7.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 4: LOGGING & MONITORING ══${NC}"

log "LOG-01: Diagnostic Settings for Activity Logs (CIS 7.1.1.1)"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
sub_id = os.environ.get("SUB_ID","")
try:
    r = subprocess.run(["az","monitor","diagnostic-settings","subscription","list","--subscription",sub_id,"--output","json"], capture_output=True, text=True, timeout=30)
    settings = json.loads(r.stdout).get("value",[]) if r.returncode == 0 else []
    with open(f"{output_dir}/diagnostic_settings.json","w") as f: json.dump(settings,f,indent=2)
    if settings:
        print(f"\033[0;32m[PASS]\033[0m LOG-01: {len(settings)} Diagnostic Setting(s) for Activity Logs (CIS 7.1.1.1)")
        for ds in settings:
            print(f"         -> {ds.get('name','?')} (workspace: {'yes' if ds.get('workspaceId') else 'no'})")
    else: print(f"\033[0;31m[FAIL]\033[0m LOG-01: NO Diagnostic Settings for Activity Logs (CIS 7.1.1.1)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m LOG-01: {e}")
PYEOF

log "LOG-02: Activity Log Alerts (CIS 7.1.2.x)"
python3 - <<'PYEOF'
import subprocess, json
ops = {
    "Microsoft.Authorization/policyAssignments/write":("LOG-02a","7.1.2.1","Create Policy"),
    "Microsoft.Authorization/policyAssignments/delete":("LOG-02b","7.1.2.2","Delete Policy"),
    "Microsoft.Network/networkSecurityGroups/write":("LOG-02c","7.1.2.3","Create/Update NSG"),
    "Microsoft.Network/networkSecurityGroups/delete":("LOG-02d","7.1.2.4","Delete NSG"),
    "Microsoft.Security/securitySolutions/write":("LOG-02e","7.1.2.5","Create Security Solution"),
    "Microsoft.Security/securitySolutions/delete":("LOG-02f","7.1.2.6","Delete Security Solution"),
    "Microsoft.Sql/servers/firewallRules/write":("LOG-02g","7.1.2.7","Create SQL FW Rule"),
    "Microsoft.Sql/servers/firewallRules/delete":("LOG-02h","7.1.2.8","Delete SQL FW Rule"),
    "Microsoft.Network/publicIPAddresses/write":("LOG-02i","7.1.2.9","Create Public IP"),
    "Microsoft.Network/publicIPAddresses/delete":("LOG-02j","7.1.2.10","Delete Public IP"),
}
try:
    r = subprocess.run(["az","monitor","activity-log","alert","list","--output","json"], capture_output=True, text=True, timeout=30)
    alerts = json.loads(r.stdout) if r.returncode == 0 else []
    configured = set()
    for a in alerts:
        if not a.get("enabled",False): continue
        for c in a.get("condition",{}).get("allOf",[]):
            if c.get("field")=="operationName": configured.add(c.get("equals",""))
    for op,(cid,ref,desc) in ops.items():
        if op in configured: print(f"\033[0;32m[PASS]\033[0m {cid}: Alert for '{desc}' (CIS {ref})")
        else: print(f"\033[0;31m[FAIL]\033[0m {cid}: No alert for '{desc}' (CIS {ref})")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m LOG-02: {e}")
PYEOF

log "LOG-03: Key Vault logging (CIS 7.1.1.4)"
python3 - <<'PYEOF'
import subprocess, json
try:
    kvr = subprocess.run(["az","keyvault","list","--output","json"], capture_output=True, text=True, timeout=30)
    vaults = json.loads(kvr.stdout) if kvr.returncode == 0 else []
    if not vaults: print(f"\033[0;34m[INFO]\033[0m LOG-03: No Key Vaults found")
    for v in vaults:
        n,vid = v.get("name","?"), v.get("id","")
        dr = subprocess.run(["az","monitor","diagnostic-settings","list","--resource",vid,"--output","json"], capture_output=True, text=True, timeout=30)
        ds = json.loads(dr.stdout).get("value",[]) if dr.returncode == 0 else []
        has_audit = any(l.get("category")=="AuditEvent" and l.get("enabled") for d in ds for l in d.get("logs",[]))
        if has_audit: print(f"\033[0;32m[PASS]\033[0m LOG-03: KV '{n}' AuditEvent logging ENABLED (CIS 7.1.1.4)")
        else: print(f"\033[0;31m[FAIL]\033[0m LOG-03: KV '{n}' AuditEvent logging NOT configured (CIS 7.1.1.4)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m LOG-03: {e}")
PYEOF

log "LOG-04: Resource Logging enabled (CIS 7.1.4)"
python3 - <<'PYEOF'
import subprocess, json
print(f"\033[1;33m[WARN]\033[0m LOG-04: Resource Logging (CIS 7.1.4) — requires per-resource diagnostic settings review")
print(f"         Run: az monitor diagnostic-settings list --resource <resource-id>")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: KEY VAULT
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 5: KEY VAULT ══${NC}"

log "KV-01/02/03/04: Key Vault configuration"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
try:
    r = subprocess.run(["az","keyvault","list","--output","json"], capture_output=True, text=True, timeout=30)
    vaults = json.loads(r.stdout) if r.returncode == 0 else []
    if not vaults: print(f"\033[0;34m[INFO]\033[0m KV: No Key Vaults found")
    else:
        with open(f"{output_dir}/keyvaults.json","w") as f: json.dump(vaults,f,indent=2)
        for v in vaults:
            n = v.get("name","?"); p = v.get("properties",v)
            if p.get("enableSoftDelete"): print(f"\033[0;32m[PASS]\033[0m KV-01: '{n}' Soft delete ENABLED")
            else: print(f"\033[0;31m[FAIL]\033[0m KV-01: '{n}' Soft delete NOT enabled")
            if p.get("enablePurgeProtection"): print(f"\033[0;32m[PASS]\033[0m KV-02: '{n}' Purge protection ENABLED")
            else: print(f"\033[0;31m[FAIL]\033[0m KV-02: '{n}' Purge protection NOT enabled")
            if p.get("enableRbacAuthorization"): print(f"\033[0;32m[PASS]\033[0m KV-03: '{n}' RBAC authorization ENABLED")
            else: print(f"\033[1;33m[WARN]\033[0m KV-03: '{n}' Using access policies (consider RBAC)")
            da = p.get("networkAcls",{}).get("defaultAction","Allow")
            if da == "Deny": print(f"\033[0;32m[PASS]\033[0m KV-04: '{n}' Network default DENY")
            else: print(f"\033[0;31m[FAIL]\033[0m KV-04: '{n}' Network default ALLOW")
            print("")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m KV: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: COMPUTE / VIRTUAL MACHINES
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 6: COMPUTE / VIRTUAL MACHINES ══${NC}"

log "VM-01/02/03: VM security checks (CIS 4.x)"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
try:
    r = subprocess.run(["az","vm","list","--show-details","--output","json"], capture_output=True, text=True, timeout=120)
    vms = json.loads(r.stdout) if r.returncode == 0 else []
    if not vms: print(f"\033[0;34m[INFO]\033[0m VM: No VMs found")
    else:
        with open(f"{output_dir}/virtual_machines.json","w") as f: json.dump(vms,f,indent=2)
        for vm in vms:
            n = vm.get("name","?")
            md = vm.get("storageProfile",{}).get("osDisk",{}).get("managedDisk",{})
            if md.get("diskEncryptionSet") or vm.get("storageProfile",{}).get("osDisk",{}).get("encryptionSettings",{}).get("enabled"):
                print(f"\033[0;32m[PASS]\033[0m VM-01: '{n}' OS disk encrypted (CMK/ADE)")
            else: print(f"\033[1;33m[WARN]\033[0m VM-01: '{n}' OS disk PMK only (consider CMK)")
            pip = vm.get("publicIps","")
            if pip: print(f"\033[1;33m[WARN]\033[0m VM-02: '{n}' PUBLIC IP: {pip}")
            else: print(f"\033[0;32m[PASS]\033[0m VM-02: '{n}' No public IP")
            it = (vm.get("identity") or {}).get("type","None")
            if it and it != "None": print(f"\033[0;32m[PASS]\033[0m VM-03: '{n}' Managed identity: {it}")
            else: print(f"\033[1;33m[WARN]\033[0m VM-03: '{n}' No managed identity")
            print("")
    print(f"\033[0;34m[INFO]\033[0m Scanned {len(vms)} VM(s)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m VM: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: APP SERVICE / WEB APPS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 7: APP SERVICE / WEB APPS ══${NC}"

log "APP-01 to APP-05: App Service checks (CIS 7.1.1.6)"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
try:
    r = subprocess.run(["az","webapp","list","--output","json"], capture_output=True, text=True, timeout=60)
    apps = json.loads(r.stdout) if r.returncode == 0 else []
    if not apps: print(f"\033[0;34m[INFO]\033[0m APP: No App Services found")
    else:
        with open(f"{output_dir}/app_services.json","w") as f: json.dump(apps,f,indent=2)
        for a in apps:
            n,rg = a.get("name","?"), a.get("resourceGroup","?")
            if a.get("httpsOnly"): print(f"\033[0;32m[PASS]\033[0m APP-01: '{n}' HTTPS-only ENABLED")
            else: print(f"\033[0;31m[FAIL]\033[0m APP-01: '{n}' HTTPS-only NOT enforced")
            try:
                cr = subprocess.run(["az","webapp","show","--name",n,"--resource-group",rg,"--output","json"], capture_output=True, text=True, timeout=30)
                cfg = json.loads(cr.stdout) if cr.returncode == 0 else {}
            except: cfg = {}
            sc = cfg.get("siteConfig",{})
            tls = sc.get("minTlsVersion","1.0")
            if tls in ("1.2","1.3"): print(f"\033[0;32m[PASS]\033[0m APP-02: '{n}' TLS {tls}")
            else: print(f"\033[0;31m[FAIL]\033[0m APP-02: '{n}' TLS {tls} — set to 1.2+")
            it = (cfg.get("identity") or {}).get("type","None")
            if it and it != "None": print(f"\033[0;32m[PASS]\033[0m APP-03: '{n}' Managed identity: {it}")
            else: print(f"\033[1;33m[WARN]\033[0m APP-03: '{n}' No managed identity")
            ftp = sc.get("ftpsState","AllAllowed")
            if ftp in ("Disabled","FtpsOnly"): print(f"\033[0;32m[PASS]\033[0m APP-04: '{n}' FTP: {ftp}")
            else: print(f"\033[0;31m[FAIL]\033[0m APP-04: '{n}' FTP: {ftp} — disable")
            if sc.get("httpLoggingEnabled"): print(f"\033[0;32m[PASS]\033[0m APP-05: '{n}' HTTP logging ENABLED (CIS 7.1.1.6)")
            else: print(f"\033[0;31m[FAIL]\033[0m APP-05: '{n}' HTTP logging NOT enabled (CIS 7.1.1.6)")
            print("")
    print(f"\033[0;34m[INFO]\033[0m Scanned {len(apps)} App Service(s)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m APP: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: DATABASE SERVICES (SQL, PostgreSQL, MySQL, Cosmos DB)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 8: DATABASE SERVICES ══${NC}"

log "DB-01 to DB-04: Azure SQL Server checks"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
try:
    r = subprocess.run(["az","sql","server","list","--output","json"], capture_output=True, text=True, timeout=30)
    servers = json.loads(r.stdout) if r.returncode == 0 else []
    if not servers: print(f"\033[0;34m[INFO]\033[0m DB-SQL: No Azure SQL Servers found")
    else:
        with open(f"{output_dir}/sql_servers.json","w") as f: json.dump(servers,f,indent=2)
        for s in servers:
            n,rg = s.get("name","?"), s.get("resourceGroup","?")
            try:
                ar = subprocess.run(["az","sql","server","audit-policy","show","--name",n,"--resource-group",rg,"--output","json"], capture_output=True, text=True, timeout=30)
                if json.loads(ar.stdout).get("state")=="Enabled": print(f"\033[0;32m[PASS]\033[0m DB-01: SQL '{n}' Auditing ENABLED")
                else: print(f"\033[0;31m[FAIL]\033[0m DB-01: SQL '{n}' Auditing NOT enabled")
            except: print(f"\033[1;33m[WARN]\033[0m DB-01: Cannot check audit for '{n}'")
            pa = s.get("publicNetworkAccess","Enabled")
            if pa == "Disabled": print(f"\033[0;32m[PASS]\033[0m DB-02: SQL '{n}' Public access DISABLED")
            else: print(f"\033[1;33m[WARN]\033[0m DB-02: SQL '{n}' Public access ENABLED")
            try:
                adr = subprocess.run(["az","sql","server","ad-admin","list","--server",n,"--resource-group",rg,"--output","json"], capture_output=True, text=True, timeout=30)
                admins = json.loads(adr.stdout) if adr.returncode == 0 else []
                if admins: print(f"\033[0;32m[PASS]\033[0m DB-03: SQL '{n}' Entra admin configured")
                else: print(f"\033[0;31m[FAIL]\033[0m DB-03: SQL '{n}' No Entra admin")
            except: print(f"\033[1;33m[WARN]\033[0m DB-03: Cannot check Entra admin for '{n}'")
            tls = s.get("minimalTlsVersion","None")
            if tls in ("1.2","1.3"): print(f"\033[0;32m[PASS]\033[0m DB-04: SQL '{n}' TLS {tls}")
            else: print(f"\033[0;31m[FAIL]\033[0m DB-04: SQL '{n}' TLS {tls} — set to 1.2+")
            print("")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m DB-SQL: {e}")
PYEOF

log "DB-05/06: PostgreSQL Flexible Server checks"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","postgres","flexible-server","list","--output","json"], capture_output=True, text=True, timeout=30)
    servers = json.loads(r.stdout) if r.returncode == 0 else []
    if not servers: print(f"\033[0;34m[INFO]\033[0m DB-PG: No PostgreSQL Flexible Servers found")
    for s in servers:
        n = s.get("name","?")
        pa = s.get("network",{}).get("publicNetworkAccess","Enabled")
        if pa == "Disabled": print(f"\033[0;32m[PASS]\033[0m DB-05: PG '{n}' Public access DISABLED")
        else: print(f"\033[1;33m[WARN]\033[0m DB-05: PG '{n}' Public access ENABLED")
        ssl = s.get("network",{}).get("requireSsl","Enabled")
        if ssl == "Enabled": print(f"\033[0;32m[PASS]\033[0m DB-06: PG '{n}' SSL REQUIRED")
        else: print(f"\033[0;31m[FAIL]\033[0m DB-06: PG '{n}' SSL NOT required")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m DB-PG: {e}")
PYEOF

log "DB-07/08: MySQL Flexible Server checks"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","mysql","flexible-server","list","--output","json"], capture_output=True, text=True, timeout=30)
    servers = json.loads(r.stdout) if r.returncode == 0 else []
    if not servers: print(f"\033[0;34m[INFO]\033[0m DB-MY: No MySQL Flexible Servers found")
    for s in servers:
        n = s.get("name","?")
        pa = s.get("network",{}).get("publicNetworkAccess","Enabled")
        if pa == "Disabled": print(f"\033[0;32m[PASS]\033[0m DB-07: MySQL '{n}' Public access DISABLED")
        else: print(f"\033[1;33m[WARN]\033[0m DB-07: MySQL '{n}' Public access ENABLED")
        tls = s.get("network",{}).get("tlsVersion","TLSv1.2")
        if "1.2" in str(tls) or "1.3" in str(tls): print(f"\033[0;32m[PASS]\033[0m DB-08: MySQL '{n}' TLS: {tls}")
        else: print(f"\033[0;31m[FAIL]\033[0m DB-08: MySQL '{n}' TLS: {tls}")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m DB-MY: {e}")
PYEOF

log "DB-09: Cosmos DB checks"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","cosmosdb","list","--output","json"], capture_output=True, text=True, timeout=30)
    accounts = json.loads(r.stdout) if r.returncode == 0 else []
    if not accounts: print(f"\033[0;34m[INFO]\033[0m DB-COSMOS: No Cosmos DB accounts found")
    for a in accounts:
        n = a.get("name","?")
        pa = a.get("publicNetworkAccess","Enabled")
        if pa == "Disabled": print(f"\033[0;32m[PASS]\033[0m DB-09a: Cosmos '{n}' Public access DISABLED")
        else: print(f"\033[1;33m[WARN]\033[0m DB-09a: Cosmos '{n}' Public access ENABLED")
        if a.get("disableLocalAuth"): print(f"\033[0;32m[PASS]\033[0m DB-09b: Cosmos '{n}' Local auth DISABLED (Entra-only)")
        else: print(f"\033[1;33m[WARN]\033[0m DB-09b: Cosmos '{n}' Local auth enabled (key-based)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m DB-COSMOS: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9: MICROSOFT DEFENDER FOR CLOUD (CIS 9.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 9: MICROSOFT DEFENDER FOR CLOUD ══${NC}"

log "DEF-01 to DEF-10: Defender for Cloud pricing tiers (CIS 9.1.x)"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
sub_id = os.environ.get("SUB_ID","")

defender_checks = {
    "VirtualMachines": ("DEF-01", "CIS 9.1.3.1", "Defender for Servers"),
    "SqlServers": ("DEF-02", "CIS 9.1.7.3", "Defender for Azure SQL"),
    "SqlServerVirtualMachines": ("DEF-03", "CIS 9.1.7.4", "Defender for SQL on Machines"),
    "AppServices": ("DEF-04", "CIS 9.1.6.1", "Defender for App Services"),
    "StorageAccounts": ("DEF-05", "CIS 9.1.5.1", "Defender for Storage"),
    "KeyVaults": ("DEF-06", "CIS 9.1.8.1", "Defender for Key Vault"),
    "Arm": ("DEF-07", "CIS 9.1.9.1", "Defender for Resource Manager"),
    "OpenSourceRelationalDatabases": ("DEF-08", "CIS 9.1.7.2", "Defender for Open-Source RDB"),
    "Containers": ("DEF-09", "CIS 9.1.4.1", "Defender for Containers"),
    "CosmosDbs": ("DEF-10", "CIS 9.1.7.1", "Defender for Cosmos DB"),
}

try:
    result = subprocess.run(
        ["az", "security", "pricing", "list", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    pricings = json.loads(result.stdout).get("value", []) if result.returncode == 0 else []

    if not pricings:
        # Try alternative format
        pricings = json.loads(result.stdout) if result.returncode == 0 else []

    with open(f"{output_dir}/defender_pricing.json", "w") as f:
        json.dump(pricings, f, indent=2)

    pricing_map = {}
    for p in pricings:
        name = p.get("name", "")
        tier = p.get("pricingTier", p.get("properties", {}).get("pricingTier", "Free"))
        pricing_map[name] = tier

    for resource_type, (check_id, cis_ref, desc) in defender_checks.items():
        tier = pricing_map.get(resource_type, "Unknown")
        if tier == "Standard":
            print(f"\033[0;32m[PASS]\033[0m {check_id}: {desc} is ON (Standard tier) ({cis_ref})")
        elif tier == "Free":
            print(f"\033[0;31m[FAIL]\033[0m {check_id}: {desc} is OFF (Free tier) — enable Standard ({cis_ref})")
        else:
            print(f"\033[1;33m[WARN]\033[0m {check_id}: {desc} tier: {tier} ({cis_ref})")

except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m DEF: Could not check Defender pricing: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10: CONDITIONAL ACCESS POLICIES (CIS 6.2.x)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 10: CONDITIONAL ACCESS POLICIES ══${NC}"

log "CA-01 to CA-04: Conditional Access policy checks (CIS 6.2.x)"
python3 - <<'PYEOF'
import subprocess, json, os
output_dir = os.environ.get("OUTPUT_DIR",".")
try:
    r = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print(f"\033[1;33m[WARN]\033[0m CA: Cannot query Conditional Access (needs Policy.Read.All)")
    else:
        policies = json.loads(r.stdout).get("value",[])
        with open(f"{output_dir}/conditional_access.json","w") as f: json.dump(policies,f,indent=2)

        enabled = [p for p in policies if p.get("state") in ("enabled","enabledForReportingButNotEnforced")]

        # CA-01: MFA for all users (CIS 6.2.4)
        has_mfa_all = False
        for p in enabled:
            conditions = p.get("conditions",{})
            users = conditions.get("users",{})
            grant = p.get("grantControls",{})
            builtins = grant.get("builtInControls",[])
            if "mfa" in builtins and "All" in users.get("includeUsers",[]):
                has_mfa_all = True
                break
        if has_mfa_all: print(f"\033[0;32m[PASS]\033[0m CA-01: MFA policy exists for all users (CIS 6.2.4)")
        else: print(f"\033[0;31m[FAIL]\033[0m CA-01: No CA policy requiring MFA for all users (CIS 6.2.4)")

        # CA-02: MFA for risky sign-ins (CIS 6.2.5)
        has_risky = False
        for p in enabled:
            conditions = p.get("conditions",{})
            risk = conditions.get("signInRiskLevels",[])
            grant = p.get("grantControls",{})
            if ("high" in risk or "medium" in risk) and "mfa" in grant.get("builtInControls",[]):
                has_risky = True; break
        if has_risky: print(f"\033[0;32m[PASS]\033[0m CA-02: MFA for risky sign-ins (CIS 6.2.5)")
        else: print(f"\033[1;33m[WARN]\033[0m CA-02: No CA policy for risky sign-in MFA (CIS 6.2.5)")

        # CA-03: MFA for admin portals (CIS 6.2.7)
        has_admin_mfa = False
        for p in enabled:
            apps = p.get("conditions",{}).get("applications",{}).get("includeApplications",[])
            grant = p.get("grantControls",{})
            # Azure Management app ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013
            if "797f4846-ba00-4fd7-ba43-dac1f8f63013" in apps and "mfa" in grant.get("builtInControls",[]):
                has_admin_mfa = True; break
        if has_admin_mfa: print(f"\033[0;32m[PASS]\033[0m CA-03: MFA for Azure Management portal (CIS 6.2.7)")
        else: print(f"\033[1;33m[WARN]\033[0m CA-03: No CA policy requiring MFA for admin portals (CIS 6.2.7)")

        # CA-04: Trusted locations defined (CIS 6.2.1)
        try:
            lr = subprocess.run(["az","rest","--method","GET","--url","https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"], capture_output=True, text=True, timeout=30)
            locs = json.loads(lr.stdout).get("value",[]) if lr.returncode == 0 else []
            trusted = [l for l in locs if l.get("isTrusted",False)]
            if trusted: print(f"\033[0;32m[PASS]\033[0m CA-04: {len(trusted)} trusted location(s) defined (CIS 6.2.1)")
            else: print(f"\033[1;33m[WARN]\033[0m CA-04: No trusted locations defined (CIS 6.2.1)")
        except: print(f"\033[1;33m[WARN]\033[0m CA-04: Cannot check named locations")

        print(f"\033[0;34m[INFO]\033[0m Total CA policies: {len(policies)} ({len(enabled)} enabled)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m CA: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11: RESOURCE LOCKS (CIS 7.2)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 11: RESOURCE LOCKS ══${NC}"

log "LOCK-01: Resource locks on critical resources (CIS 7.2)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","lock","list","--output","json"], capture_output=True, text=True, timeout=30)
    locks = json.loads(r.stdout) if r.returncode == 0 else []
    if locks:
        delete_locks = [l for l in locks if l.get("level")=="CanNotDelete"]
        readonly_locks = [l for l in locks if l.get("level")=="ReadOnly"]
        print(f"\033[0;32m[PASS]\033[0m LOCK-01: {len(locks)} resource lock(s) configured ({len(delete_locks)} CanNotDelete, {len(readonly_locks)} ReadOnly) (CIS 7.2)")
    else:
        print(f"\033[0;31m[FAIL]\033[0m LOCK-01: No resource locks configured — add locks to mission-critical resources (CIS 7.2)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m LOCK-01: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12: NSG FLOW LOGS (CIS 8.5 / 8.8)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 12: NSG FLOW LOGS ══${NC}"

log "FLOW-01: NSG Flow Log retention (CIS 8.5)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","network","watcher","flow-log","list","--output","json"], capture_output=True, text=True, timeout=30)
    flowlogs = json.loads(r.stdout) if r.returncode == 0 else []
    if not flowlogs:
        print(f"\033[0;31m[FAIL]\033[0m FLOW-01: No NSG Flow Logs configured (CIS 8.5)")
    else:
        for fl in flowlogs:
            n = fl.get("name","?")
            enabled = fl.get("enabled",False)
            retention = fl.get("retentionPolicy",{})
            ret_enabled = retention.get("enabled",False)
            ret_days = retention.get("days",0)
            analytics = fl.get("flowAnalyticsConfiguration",{}).get("networkWatcherFlowAnalyticsConfiguration",{}).get("enabled",False)

            if not enabled:
                print(f"\033[0;31m[FAIL]\033[0m FLOW-01: '{n}' Flow Log DISABLED")
            elif ret_enabled and ret_days >= 90:
                print(f"\033[0;32m[PASS]\033[0m FLOW-01: '{n}' Retention {ret_days} days (>=90) (CIS 8.5)")
            elif ret_enabled:
                print(f"\033[0;31m[FAIL]\033[0m FLOW-01: '{n}' Retention only {ret_days} days — need >=90 (CIS 8.5)")
            else:
                print(f"\033[1;33m[WARN]\033[0m FLOW-01: '{n}' Retention policy not configured")

            if analytics:
                print(f"\033[0;32m[PASS]\033[0m FLOW-02: '{n}' Traffic Analytics ENABLED")
            else:
                print(f"\033[1;33m[WARN]\033[0m FLOW-02: '{n}' Traffic Analytics NOT enabled — consider enabling (CIS 7.1.1.5)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m FLOW: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 13: AZURE BASTION (CIS 9.4.1)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 13: AZURE BASTION ══${NC}"

log "BASTION-01: Azure Bastion Host (CIS 9.4.1)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","network","bastion","list","--output","json"], capture_output=True, text=True, timeout=30)
    bastions = json.loads(r.stdout) if r.returncode == 0 else []
    if bastions:
        print(f"\033[0;32m[PASS]\033[0m BASTION-01: {len(bastions)} Azure Bastion Host(s) deployed (CIS 9.4.1)")
        for b in bastions: print(f"         -> {b.get('name','?')} ({b.get('location','?')})")
    else:
        print(f"\033[0;31m[FAIL]\033[0m BASTION-01: No Azure Bastion Hosts — deploy for secure VM access (CIS 9.4.1)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m BASTION-01: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 14: AZURE CONTAINER REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 14: CONTAINER REGISTRY ══${NC}"

log "ACR-01/02/03: Container Registry checks"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","acr","list","--output","json"], capture_output=True, text=True, timeout=30)
    registries = json.loads(r.stdout) if r.returncode == 0 else []
    if not registries: print(f"\033[0;34m[INFO]\033[0m ACR: No Container Registries found")
    for reg in registries:
        n = reg.get("name","?")
        if not reg.get("adminUserEnabled",True): print(f"\033[0;32m[PASS]\033[0m ACR-01: '{n}' Admin user DISABLED")
        else: print(f"\033[0;31m[FAIL]\033[0m ACR-01: '{n}' Admin user ENABLED — disable for production")
        pa = reg.get("publicNetworkAccess","Enabled")
        if pa == "Disabled": print(f"\033[0;32m[PASS]\033[0m ACR-02: '{n}' Public access DISABLED")
        else: print(f"\033[1;33m[WARN]\033[0m ACR-02: '{n}' Public access ENABLED")
        sku = reg.get("sku",{}).get("name","Basic")
        if sku == "Premium": print(f"\033[0;32m[PASS]\033[0m ACR-03: '{n}' SKU: Premium (supports private endpoints)")
        else: print(f"\033[1;33m[WARN]\033[0m ACR-03: '{n}' SKU: {sku} — Premium required for private endpoints & content trust")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m ACR: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 15: AZURE KUBERNETES SERVICE
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 15: AZURE KUBERNETES SERVICE ══${NC}"

log "AKS-01/02/03/04: AKS cluster checks"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","aks","list","--output","json"], capture_output=True, text=True, timeout=30)
    clusters = json.loads(r.stdout) if r.returncode == 0 else []
    if not clusters: print(f"\033[0;34m[INFO]\033[0m AKS: No AKS clusters found")
    for c in clusters:
        n = c.get("name","?")
        # AKS-01: RBAC enabled
        if c.get("enableRbac",False): print(f"\033[0;32m[PASS]\033[0m AKS-01: '{n}' Kubernetes RBAC ENABLED")
        else: print(f"\033[0;31m[FAIL]\033[0m AKS-01: '{n}' RBAC NOT enabled")
        # AKS-02: Network policy
        np = c.get("networkProfile",{}).get("networkPolicy","")
        if np: print(f"\033[0;32m[PASS]\033[0m AKS-02: '{n}' Network policy: {np}")
        else: print(f"\033[1;33m[WARN]\033[0m AKS-02: '{n}' No network policy configured")
        # AKS-03: Private cluster
        api_access = c.get("apiServerAccessProfile",{})
        if api_access.get("enablePrivateCluster",False): print(f"\033[0;32m[PASS]\033[0m AKS-03: '{n}' Private cluster ENABLED")
        else: print(f"\033[1;33m[WARN]\033[0m AKS-03: '{n}' Public API server — consider private cluster")
        # AKS-04: Managed identity
        it = c.get("identity",{}).get("type","None")
        if it and it != "None": print(f"\033[0;32m[PASS]\033[0m AKS-04: '{n}' Managed identity: {it}")
        else: print(f"\033[1;33m[WARN]\033[0m AKS-04: '{n}' Using service principal — migrate to managed identity")
        # AKS-05: Defender for Containers profile
        sp = c.get("securityProfile",{})
        defender = sp.get("defender",{})
        if defender.get("securityMonitoring",{}).get("enabled",False): print(f"\033[0;32m[PASS]\033[0m AKS-05: '{n}' Defender monitoring ENABLED")
        else: print(f"\033[1;33m[WARN]\033[0m AKS-05: '{n}' Defender monitoring not detected")
        print("")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m AKS: {e}")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 16: MISCELLANEOUS (Disk Encryption, Public IPs, Application Insights)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SECTION 16: MISCELLANEOUS SECURITY CHECKS ══${NC}"

log "MISC-01: Unattached managed disks encryption"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","disk","list","--query","[?diskState=='Unattached']","--output","json"], capture_output=True, text=True, timeout=30)
    disks = json.loads(r.stdout) if r.returncode == 0 else []
    if not disks: print(f"\033[0;32m[PASS]\033[0m MISC-01: No unattached managed disks")
    else:
        for d in disks:
            n = d.get("name","?")
            enc = d.get("encryption",{}).get("type","")
            if "CustomerKey" in enc: print(f"\033[0;32m[PASS]\033[0m MISC-01: Unattached disk '{n}' encrypted with CMK")
            else: print(f"\033[1;33m[WARN]\033[0m MISC-01: Unattached disk '{n}' using {enc or 'platform keys'} — consider CMK or delete")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m MISC-01: {e}")
PYEOF

log "MISC-02: Orphaned public IPs"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","network","public-ip","list","--output","json"], capture_output=True, text=True, timeout=30)
    pips = json.loads(r.stdout) if r.returncode == 0 else []
    orphaned = [p for p in pips if not p.get("ipConfiguration")]
    if not orphaned: print(f"\033[0;32m[PASS]\033[0m MISC-02: No orphaned public IPs ({len(pips)} total)")
    else:
        print(f"\033[1;33m[WARN]\033[0m MISC-02: {len(orphaned)} orphaned public IP(s) — review and delete unused")
        for p in orphaned: print(f"         -> {p.get('name','?')} ({p.get('ipAddress','?')})")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m MISC-02: {e}")
PYEOF

log "MISC-03: Application Insights (CIS 7.1.3.1)"
python3 - <<'PYEOF'
import subprocess, json
try:
    r = subprocess.run(["az","monitor","app-insights","component","list","--output","json"], capture_output=True, text=True, timeout=30)
    components = json.loads(r.stdout) if r.returncode == 0 else []
    if components:
        print(f"\033[0;32m[PASS]\033[0m MISC-03: {len(components)} Application Insights instance(s) configured (CIS 7.1.3.1)")
    else:
        print(f"\033[1;33m[WARN]\033[0m MISC-03: No Application Insights configured — enable for web app monitoring (CIS 7.1.3.1)")
except Exception as e: print(f"\033[1;33m[WARN]\033[0m MISC-03: {e}")
PYEOF

log "MISC-04: Microsoft Defender External Attack Surface Monitoring (CIS 9.1.16)"
python3 - <<'PYEOF'
print(f"\033[1;33m[WARN]\033[0m MISC-04: Defender EASM (CIS 9.1.16) — verify in Azure Portal > Microsoft Defender for Cloud > Environment settings")
PYEOF


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "======================================================================"
echo -e " AUDIT COMPLETE — Enhanced Script (16 Sections)"
echo -e " ${GREEN}PASS : $PASS${NC}"
echo -e " ${RED}FAIL : $FAIL${NC}"
echo -e " ${YELLOW}WARN : $WARN${NC}"
echo -e " Total: $((PASS + FAIL + WARN))"
echo " Evidence: $OUTPUT_DIR/"
echo "======================================================================"

# Write manifest
{
    echo "Azure Security Audit — Enhanced Evidence Manifest"
    echo "================================================="
    echo "Date       : $(date)"
    echo "Subscription: $SUB_NAME ($SUB_ID)"
    echo "Tenant     : $TENANT_ID"
    echo "Script     : azure_security_audit_enhanced.sh (16 Sections)"
    echo "Benchmark  : CIS Microsoft Azure Foundations v4.0.0"
    echo "Results    : PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
    echo ""
    echo "Evidence files:"
    ls -la "$OUTPUT_DIR/" 2>/dev/null | tail -n +4
} > "$OUTPUT_DIR/AUDIT_MANIFEST.txt"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
