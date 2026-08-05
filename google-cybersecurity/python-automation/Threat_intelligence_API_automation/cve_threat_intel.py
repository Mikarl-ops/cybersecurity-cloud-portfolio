"""
Filename: cve_threat_intel.py
Description: Queries the NVD API to retrieve recent High/Critical vulnerabilities
             for automated patch prioritization and threat tracking.
"""

import urllib.request
import json

def fetch_critical_cves(keyword, max_results=3):
    url = f"https://services.nvd.nist.gov/rest/json/cves/20.0?keywordSearch={keyword}&resultsPerPage={max_results}"
    headers = {"User-Agent": "SecurityPortfolioScript/1.0"}
    
    print(f"[*] Querying NVD Threat Feed for keyword: '{keyword}'...")
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                print("[*] No matching vulnerabilities found.")
                return

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                description = cve.get("descriptions", [{}])[0].get("value", "No description available.")
                print(f"\n[CVE IDENTIFIED] {cve_id}")
                print(f"Description: {description[:160]}...")
                
    except Exception as e:
        print(f"[ERROR] Threat intelligence query failed: {e}")

if __name__ == "__main__":
    fetch_critical_cves("terraform", max_results=2)