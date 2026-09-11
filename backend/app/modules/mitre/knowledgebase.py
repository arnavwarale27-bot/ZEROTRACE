from typing import Dict, Any

# Standard MITRE ATT&CK Enterprise Matrix Technique Dictionary
MITRE_KNOWLEDGEBASE: Dict[str, Dict[str, str]] = {
    # Initial Access
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, bugs, glitches, or vulnerabilities in order to cause unintended or unanticipated behavior.",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    # Execution
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse the Windows command shell (cmd.exe) for execution. Cmd.exe is the primary command-line interpreter on Windows systems.",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious code with signed or trusted system binaries such as rundll32.exe.",
        "url": "https://attack.mitre.org/techniques/T1218/",
    },
    # Persistence
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding a program to a registry run key or the startup folder to cause the program to be executed when a user logs in.",
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    # Defense Evasion
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or script difficult to discover or analyze by encoding, encrypting, or otherwise obfuscating its contents.",
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or impede defensive mechanisms.",
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    # Credential Access
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes cannot be cracked.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    # Discovery
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of valid accounts on a system or within an environment.",
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, and architecture.",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    # Command and Control
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection/network filtering by blending in with existing traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection and network filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "description": "Adversaries may tunnel network communications through a non-standard or permitted protocol to disguise malicious command and control or exfiltration.",
        "url": "https://attack.mitre.org/techniques/T1572/",
    },
}
