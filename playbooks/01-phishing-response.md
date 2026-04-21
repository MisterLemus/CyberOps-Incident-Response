# Playbook: Phishing Email Response
**MITRE ATT&CK:** T1566 (Phishing) | **Severity:** HIGH | **SLA:** 30 min

## Detection
- SIEM alert: suspicious email attachment/link
- User report to helpdesk
- Email gateway quarantine notification

## Triage (5 min)
- [ ] Identify sender (check SPF, DKIM, DMARC)
- [ ] Analyze headers (X-Originating-IP)
- [ ] Check URL reputation (VirusTotal, URLscan.io)
- [ ] Check attachment hash (VirusTotal)

## Containment (15 min)
- [ ] Block sender domain in email gateway
- [ ] Block malicious URL in proxy/firewall
- [ ] Search for same email across all mailboxes
- [ ] Delete from all inboxes (Exchange: Search-Mailbox -DeleteContent)
- [ ] If clicked: isolate endpoint from network

## Eradication
- [ ] If credentials entered: force password reset + revoke sessions
- [ ] If malware downloaded: full AV scan + check persistence
- [ ] Block IOCs (IPs, domains, hashes) in all security tools
- [ ] Update email filtering rules

## Recovery
- [ ] Verify endpoint clean (EDR scan)
- [ ] Re-enable network access
- [ ] Monitor for suspicious activity (48h)

## Lessons Learned
- [ ] Update phishing training
- [ ] Add detection rule for this pattern
- [ ] Document IOCs in threat intel platform
