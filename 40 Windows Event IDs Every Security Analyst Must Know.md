
## Why Event IDs Matter in Security

Windows Event Logs are like a diary for your machine — every login, every file access, every error gets recorded. But not every event is useful for security investigations. By focusing on key Event IDs, you can quickly:

- Detect suspicious logins and account activity
- Spot privilege escalations or changes
- Catch malware behaviors early
- Speed up incident response

## The Must-Know Windows Event IDs

1. **4624 — Successful Logon**  
    Shows every time someone logs in. Watch for odd hours, unexpected accounts, or logins from unusual sources (e.g., foreign IPs).
    
2. **4625 — Failed Logon**  
    Failed login attempts can signal brute-force attacks, credential stuffing, or misconfigured services.
    
3. **4647 — User Initiated Logoff**  
    Tracks when users log off, useful for correlating session durations and detecting abnormal session terminations.
    
4. **4672 — Special Privilege Assigned to New Logon**  
    Indicates a login with admin or elevated rights, critical for spotting privilege escalation attempts.
    
5. **4720 — User Account Created**  
    New accounts might be legitimate or backdoors created by attackers for persistence.
    
6. **4722 — User Account Enabled**  
    Tracks when an account is enabled, which could indicate unauthorized reactivation of disabled accounts.
    
7. **4723 — Password Change Attempt**  
    Detects attempts to change passwords, useful for identifying unauthorized resets or insider threats.
    
8. **4724 — Password Reset Attempt**  
    Tracks when an administrator resets a user’s password, which could indicate malicious activity if unexpected.
    
9. **1102 — Security Log Cleared**  
    Indicates the security event log was cleared, a common tactic by attackers to cover their tracks.
    
10. **4616 — System Time Changed**  
    Detects changes to the system time, which could be used to manipulate logs or evade time-based security controls.
    
11. **4657 — Registry Value Modified**  
    Tracks modifications to registry keys, often used by malware for persistence or configuration changes.
    
12. **4663 — File System Object Access**  
    Indicates access to files or directories, useful for tracking sensitive file access or data exfiltration attempts.
    
13. **4688 — Process Creation**  
    Logs when a new process is created, critical for identifying suspicious or malicious process execution.
    
14. **4697 — Service Installed**  
    Detects new services installed on the system, which could indicate malware persistence mechanisms.
    
15. **4700 — Scheduled Task Created**  
    Tracks creation of scheduled tasks, often used by attackers for persistence or remote execution.
    
16. **4702 — Scheduled Task Updated**  
    Monitors updates to scheduled tasks, which could indicate tampering by malicious actors.
    
17. **4732 — User Added to Security Group**  
    Indicates a user was added to a group (e.g., Administrators), critical for detecting privilege escalation.
    
18. **4738 — User Account Changed**  
    Tracks changes to user account attributes, such as enabling, disabling, or modifying privileges.
    
19. **4740 — Account Lockout**  
    Detects account lockouts, which could indicate brute-force attacks or misconfigured accounts.
    
20. **4768 — Kerberos Authentication Ticket Granted**  
    Logs successful Kerberos ticket requests, useful for tracking authentication anomalies.
    
21. **4771 — Kerberos Pre-Authentication Failed**  
    Indicates failed Kerberos authentication, which could signal brute-force or credential misuse.
    
22. **4776 — Credential Validation**  
    Tracks NTLM authentication attempts, useful for detecting lateral movement or pass-the-hash attacks.
    
23. **5140 — Network Share Accessed**  
    Logs access to network shares, critical for detecting unauthorized access or data exfiltration.
    
24. **5156 — Windows Filtering Platform Connection**  
    Tracks network connections allowed or blocked by the Windows firewall, useful for monitoring network activity.
    
25. **7045 — New Service Installed**  
    Detects new services added to the system, a common persistence mechanism for malware.
    
26. **4661 — SAM Object Access**  
    Indicates access to Security Account Manager (SAM) objects, useful for detecting attempts to dump credentials.
    
27. **4673 — Sensitive Privilege Use**  
    Tracks the use of sensitive privileges (e.g., SeDebugPrivilege), which could indicate privilege escalation.
    
28. **4689 — Process Termination**  
    Logs when a process terminates, useful for correlating with process creation events to detect short-lived malicious processes.
    
29. **4698 — Scheduled Task Created (Detailed)**  
    Provides detailed information about scheduled task creation, including the command executed.
    
30. **4703 — Token Right Adjusted**  
    Tracks adjustments to user token privileges, which could indicate attempts to elevate access.
    
31. **4719 — Audit Policy Changed**  
    Detects changes to audit policies, which attackers may modify to reduce logging.
    
32. **4728 — User Added to Privileged Group**  
    Indicates a user was added to a privileged group (e.g., Domain Admins), a key indicator of compromise.
    
33. **4735 — Security Group Modified**  
    Tracks changes to security groups, critical for detecting unauthorized group membership changes.
    
34. **4742 — Computer Account Changed**  
    Logs changes to computer accounts, which could indicate tampering in Active Directory environments.
    
35. **4964 — Special Logon Groups Assigned**  
    Tracks assignment of special logon groups, useful for detecting targeted privilege escalations.
    
36. **5158 — Windows Filtering Platform Permitted Bind**  
    Indicates a process binding to a local port, useful for detecting unauthorized services or backdoors.
    
37. **6005 — Event Log Service Started**  
    Logs when the event log service starts, useful for correlating system boot or service restart events.
    
38. **6006 — Event Log Service Stopped**  
    Indicates the event log service was stopped, which could be an attempt to evade logging.
    
39. **4648 — Explicit Credential Use**  
    Tracks when a user explicitly provides credentials (e.g., RunAs), which could indicate lateral movement.
    
40. **4674 — Sensitive Privilege Assigned to Object**  
    Logs assignment of sensitive privileges to objects, critical for detecting advanced privilege escalation attempts.