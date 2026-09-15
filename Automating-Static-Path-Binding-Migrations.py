import requests
import json
import urllib3
import re

# Disable unverified HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
APIC_URL = "https://172.29.197.133"
USERNAME = "USERNAME"
PASSWORD = "PASSWORD" # <-- Drop your password inside these quotes

# The Distinguished Name (DN) of your source vPC
SOURCE_VPC_TDN = "topology/pod-1/protpaths-311-312/pathep-[VPC-E22_TS5VS2SW222_225-IAAS2_TRAFFIC]"

# The Distinguished Names (DNs) of your two new destination vPCs
DEST_VPC_LIST = [
    "topology/pod-1/protpaths-311-312/pathep-[VPC-E22_TS5VS2SW222-IAAS2_TRAFFIC]",
    "topology/pod-1/protpaths-311-312/pathep-[VPC-E22_TS5VS2SW225-IAAS2_TRAFFIC]"
]

# 🛑 SAFETY SWITCH: True = Test/Preview, False = Live Write to APIC
DRY_RUN = True

# --- 1. Authenticate ---
session = requests.Session()
login_url = f"{APIC_URL}/api/aaaLogin.json"
login_payload = {"aaaUser": {"attributes": {"name": USERNAME, "pwd": PASSWORD}}}
response = session.post(login_url, json=login_payload, verify=False)
response.raise_for_status()

# --- 2. Query Existing Bindings ---
query_url = f"{APIC_URL}/api/node/class/fvRsPathAtt.json?query-target-filter=eq(fvRsPathAtt.tDn,\"{SOURCE_VPC_TDN}\")"
get_resp = session.get(query_url, verify=False)
source_bindings = get_resp.json()['imdata']

print("=========================================================")
print(f"🚀 ACI v6.0 EXECUTION: Found {len(source_bindings)} EPGs on Old vPC.")
if DRY_RUN:
    print("🛑 STATUS: DRY RUN ENABLED. Review findings below before going live.")
else:
    print("⚠️ STATUS: LIVE DEPLOYMENT ACTIVE. Writing directly to APIC.")
print("=========================================================\n")

# --- 3. Duplicate Bindings ---
for item in source_bindings:
    attributes = item['fvRsPathAtt']['attributes']
    original_dn = attributes['dn']

    # Safe parent EPG extraction (Case-insensitive to prevent APIC 6.0 string splitting bugs)
    match = re.split(r'/rspathatt', original_dn, flags=re.IGNORECASE)
    epg_dn = match[0]

    # Loop through each target new vPC profile
    for target_vpc_tdn in DEST_VPC_LIST:
        if DRY_RUN:
            print(f"WOULD CLONE EPG: {epg_dn}")
            print(f"    └─ Encap: {attributes.get('encap', 'N/A')}")
            print(f"    └─ Mode: {attributes.get('mode', 'regular')}")
            print(f"    └─ Destination: {target_vpc_tdn}\n")
        else:
            # Construct the static path binding payload
            new_binding_payload = {
                "fvRsPathAtt": {
                    "attributes": {
                        "tDn": target_vpc_tdn,
                        "encap": attributes.get('encap'),
                        "mode": attributes.get('mode', 'regular'),
                        "instrImedcy": attributes.get('instrImedcy', 'lazy')
                    }
                }
            }

            # Post updates directly to the parent EPG endpoint
            post_url = f"{APIC_URL}/api/node/mo/{epg_dn}.json"
            post_resp = session.post(post_url, json=new_binding_payload, verify=False)

            # Clean up the output string name to make it brief on screen
            short_vpc_name = target_vpc_tdn.split('pathep-[')[1].replace(']', '')
            if post_resp.status_code == 200:
                print(f"✅ Cloned EPG binding to [{short_vpc_name}] for EPG: {epg_dn.split('/ap-')[1]}")
            else:
                print(f"❌ Failed cloning to [{short_vpc_name}] for EPG {epg_dn}: {post_resp.text}")

print("=========================================================")
if DRY_RUN:
    print("✅ Dry run finished safely. To apply changes, edit the file and set DRY_RUN = False.")
else:
    print("✅ Active deployment finished.")
print("=========================================================")