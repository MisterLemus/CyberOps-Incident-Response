#!/usr/bin/env python3
"""
IOC (Indicators of Compromise) Extractor
Author: José Carol Lemus Reyes
Extracts IPs, domains, URLs, hashes, emails from text/logs
"""
import re
import sys
import json
from collections import Counter

PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|info|biz|xyz|top|ru|cn|tk)\b',
    "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
}

# Known safe/internal to exclude
WHITELIST = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "localhost", 
             "google.com", "microsoft.com", "github.com"}

def extract_iocs(text):
    results = {}
    for ioc_type, pattern in PATTERNS.items():
        matches = set(re.findall(pattern, text, re.IGNORECASE))
        filtered = {m for m in matches if m.lower() not in WHITELIST}
        if filtered:
            results[ioc_type] = sorted(filtered)
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ioc-extractor.py <file>")
        print("Extracts IOCs (IPs, domains, URLs, hashes, emails) from text files")
        sys.exit(1)
    
    with open(sys.argv[1], 'r', errors='ignore') as f:
        content = f.read()
    
    iocs = extract_iocs(content)
    
    print(f"\n{'='*50}")
    print(f"  IOC EXTRACTION REPORT")
    print(f"  File: {sys.argv[1]}")
    print(f"{'='*50}")
    
    total = 0
    for ioc_type, values in iocs.items():
        print(f"\n[{ioc_type.upper()}] ({len(values)} found)")
        for v in values[:20]:
            print(f"  • {v}")
        if len(values) > 20:
            print(f"  ... and {len(values)-20} more")
        total += len(values)
    
    print(f"\n{'='*50}")
    print(f"  Total IOCs extracted: {total}")
    
    output = f"iocs_{sys.argv[1].split('/')[-1]}.json"
    with open(output, "w") as f:
        json.dump(iocs, f, indent=2)
    print(f"  Exported to: {output}")

if __name__ == "__main__":
    main()
