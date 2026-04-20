# MITRE ATT&CK Quick Reference for Alert Triage

Use this lookup when mapping observed behavior to ATT&CK. This is a curated
shortlist of the techniques most frequently seen in enterprise SOC telemetry.

## Initial Access (TA0001)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Phishing | T1566 | Attachment detonation, suspicious link clicks from mail gateway |
| Valid Accounts | T1078 | Impossible travel, MFA fatigue, stale account reactivation |
| Exploit Public-Facing App | T1190 | WAF blocks, unusual POST bodies, webshell drops |

## Execution (TA0002)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| PowerShell | T1059.001 | `powershell -enc`, `-nop -w hidden`, downloaded scriptblock logs |
| Windows Command Shell | T1059.003 | `cmd /c`, parent is Office/browser |
| WMI | T1047 | `wmic process call create`, remote WMI from non-admin host |
| Scheduled Task | T1053.005 | `schtasks /create`, unusual task author |

## Persistence (TA0003)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Registry Run Keys | T1547.001 | HKCU/HKLM ...\Run modifications |
| Scheduled Task | T1053.005 | Tasks pointing to user-writable paths |
| Valid Accounts | T1078 | New service accounts, krbtgt password changes |

## Privilege Escalation (TA0004)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Token Impersonation | T1134 | `SeImpersonatePrivilege` abuse, Potato family |
| Abuse UAC Bypass | T1548.002 | fodhelper, eventvwr, sdclt spawning cmd |
| Exploitation for Priv Esc | T1068 | PrintNightmare, ZeroLogon indicators |

## Defense Evasion (TA0005)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Obfuscated Files | T1027 | Base64 PowerShell, XOR'd payloads |
| Indicator Removal | T1070 | wevtutil cl, file timestomp |
| Masquerading | T1036 | svchost.exe not in System32, spoofed PPIDs |
| Process Injection | T1055 | CreateRemoteThread, reflective DLL load |

## Credential Access (TA0006)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| OS Credential Dumping | T1003 | lsass access by non-svchost, Mimikatz strings |
| Brute Force | T1110 | >N failed logons from single source |
| Kerberoasting | T1558.003 | TGS requests for SPN with RC4 |

## Discovery (TA0007)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| System Info Discovery | T1082 | `systeminfo`, `hostname`, `whoami /all` |
| Domain Trust Discovery | T1482 | `nltest /domain_trusts`, BloodHound collectors |
| Network Share Discovery | T1135 | `net view`, `net share` |

## Lateral Movement (TA0008)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Remote Services SMB | T1021.002 | admin$ writes from non-admin workstations |
| RDP | T1021.001 | Interactive logon type 10 from unusual source |
| Pass the Hash | T1550.002 | NTLM auth without corresponding Kerberos |

## Collection (TA0009)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Archive Collected Data | T1560 | rar, 7z, makecab with recent timestamps |
| Data from Local System | T1005 | Mass file reads, ShellBags anomalies |

## C2 (TA0011)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| App Layer Protocol Web | T1071.001 | Beacon-like HTTP intervals, rare user-agent |
| DNS | T1071.004 | Long TXT queries, high-entropy subdomains |
| Encrypted Channel | T1573 | TLS to low-reputation ASN, self-signed certs |

## Exfiltration (TA0010)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Exfil Over C2 | T1041 | Outbound volume spike on C2 channel |
| Exfil to Cloud Storage | T1567.002 | Uploads to mega.nz, anonfiles, unsanctioned S3 |

## Impact (TA0040)

| Technique | ID | Common signals |
|-----------|-----|----------------|
| Data Encrypted (ransomware) | T1486 | Mass file extension changes, ransom notes |
| Inhibit System Recovery | T1490 | vssadmin delete shadows, wbadmin delete |
| Account Access Removal | T1531 | Mass password resets, admin account lockouts |

## Mapping heuristics

- **Parent-child process mismatch** → almost always Defense Evasion (T1036 or T1055)
- **Encoded command line** → T1027 (Obfuscated) + T1059 (executor)
- **LOLBins** (certutil, bitsadmin, regsvr32) → usually T1218 Signed Binary Proxy
- **Outbound beaconing** → T1071 variants, identify protocol first
- When in doubt between a sub-technique and its parent, cite the parent and note the sub-technique as "likely"
