# https://docs.opnsense.org/development/api.html API DOCUMENTATION OPNsense

import requests
import os
import json
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# .env file with API_KEY, API_SECRET, and OPNSENSE_IP
load_dotenv()

# Store the variable from the .env file in the script
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

# List of common OPNsense API endpoints
endpoints = [
    # Firewall Alias

    "/api/firewall/alias/export",
    "/api/firewall/alias/get",
    "/api/firewall/alias/getAliasUUID",
    "/api/firewall/alias/getGeoIP",
    "/api/firewall/alias/getItem",
    "/api/firewall/alias/getTableSize",

    "/api/firewall/alias/listNetworkAliases",

    "/api/firewall/alias/searchItem",


    "/api/firewall/category/get",
    "/api/firewall/category/getItem",
    "/api/firewall/category/searchItem",


    "/api/firewall/filter_base/get",


    "/api/firewall/filter/getRule",
    "/api/firewall/filter/searchRule",

    "/api/firewall/filter_util/ruleStats",

    "/api/firewall/group/addItem",
    "/api/firewall/group/delItem",
    "/api/firewall/group/get",
    "/api/firewall/group/getItem",
    "/api/firewall/group/reconfigure",
    "/api/firewall/group/searchItem",
    "/api/firewall/group/set",
    "/api/firewall/group/setItem",

    "/api/firewall/npt/getRule",
    "/api/firewall/npt/searchRule",

    "/api/firewall/one_to_one/addRule",
    "/api/firewall/one_to_one/delRule",
    "/api/firewall/one_to_one/getRule",
    "/api/firewall/one_to_one/searchRule",
    "/api/firewall/one_to_one/setRule",
    "/api/firewall/one_to_one/toggleRule",

    "/api/firewall/source_nat/addRule",
    "/api/firewall/source_nat/delRule",
    "/api/firewall/source_nat/getRule",
    "/api/firewall/source_nat/searchRule",
    "/api/firewall/source_nat/setRule",
    "/api/firewall/source_nat/toggleRule",
    "/api/firewall/filter/searchRule"
]


# Iterate through each API endpoint and check response
for endpoint in endpoints:
    url = f"{OPNSENSE_IP}{endpoint}"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem", timeout=5)
        if response.status_code == 200:
            json_data = response.json()
            print(f"✅ SUCCESS: {endpoint} - Response: {json.dumps(json_data, indent=2)[:5000]}...")  # Print first 500 chars
        else:
            print(f"❌ ERROR: {endpoint} - {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ REQUEST FAILED: {endpoint} - {str(e)}")

print("\n🎯 API Scan Complete!")