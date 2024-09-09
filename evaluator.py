import re
# from sentence_transformers import SentenceTransformer
import yaml

tactic_name_to_id = {"Reconnaissance": "TA0043", "Resource Development": "TA0042", "Initial Access": "TA0001",
                     "Execution": "TA0002", "Persistence": "TA0003", "Privilege Escalation": "TA0004",
                     "Defense Evasion": "TA0005", "Credential Access": "TA0006", "Discovery": "TA0007",
                     "Lateral Movement": "TA0008", "Collection": "TA0009", "Command and Control": "TA0011",
                     "Exfiltration": "TA0010", "Impact": "TA0040"}

technique_id_to_name = {"T1595": "Active Scanning", "T1592": "Gather Victim Host Information",
                        "T1589": "Gather Victim Identity Information", "T1590": "Gather Victim Network Information",
                        "T1591": "Gather Victim Org Information", "T1598": "Phishing for Information",
                        "T1597": "Search Closed Sources", "T1596": "Search Open Technical Databases",
                        "T1593": "Search Open Websites/Domains", "T1594": "Search Victim-Owned Websites",
                        "T1650": "Acquire Access", "T1583": "Acquire Infrastructure", "T1586": "Compromise Accounts",
                        "T1584": "Compromise Infrastructure", "T1587": "Develop Capabilities",
                        "T1585": "Establish Accounts", "T1588": "Obtain Capabilities", "T1608": "Stage Capabilities",
                        "T1659": "Content Injection", "T1189": "Drive-by Compromise",
                        "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services",
                        "T1200": "Hardware Additions", "T1566": "Phishing",
                        "T1091": "Replication Through Removable Media", "T1195": "Supply Chain Compromise",
                        "T1199": "Trusted Relationship", "T1078": "Valid Accounts",
                        "T1651": "Cloud Administration Command", "T1059": "Command and Scripting Interpreter",
                        "T1609": "Container Administration Command", "T1610": "Deploy Container",
                        "T1203": "Exploitation for Client Execution", "T1559": "Inter-Process Communication",
                        "T1106": "Native API", "T1053": "Scheduled Task/Job", "T1648": "Serverless Execution",
                        "T1129": "Shared Modules", "T1072": "Software Deployment Tools", "T1569": "System Services",
                        "T1204": "User Execution", "T1047": "Windows Management Instrumentation",
                        "T1098": "Account Manipulation", "T1197": "BITS Jobs",
                        "T1547": "Boot or Logon Autostart Execution", "T1037": "Boot or Logon Initialization Scripts",
                        "T1176": "Browser Extensions", "T1554": "Compromise Client Software Binary",
                        "T1136": "Create Account", "T1543": "Create or Modify System Process",
                        "T1546": "Event Triggered Execution", "T1574": "Hijack Execution Flow",
                        "T1525": "Implant Internal Image", "T1556": "Modify Authentication Process",
                        "T1137": "Office Application Startup", "T1653": "Power Settings", "T1542": "Pre-OS Boot",
                        "T1505": "Server Software Component", "T1205": "Traffic Signaling",
                        "T1548": "Abuse Elevation Control Mechanism", "T1134": "Access Token Manipulation",
                        "T1484": "Domain Policy Modification", "T1611": "Escape to Host",
                        "T1068": "Exploitation for Privilege Escalation", "T1055": "Process Injection",
                        "T1612": "Build Image on Host", "T1622": "Debugger Evasion",
                        "T1140": "Deobfuscate/Decode Files or Information", "T1006": "Direct Volume Access",
                        "T1480": "Execution Guardrails", "T1211": "Exploitation for Defense Evasion",
                        "T1222": "File and Directory Permissions Modification", "T1564": "Hide Artifacts",
                        "T1562": "Impair Defenses", "T1656": "Impersonation", "T1070": "Indicator Removal",
                        "T1202": "Indirect Command Execution", "T1036": "Masquerading",
                        "T1578": "Modify Cloud Compute Infrastructure", "T1112": "Modify Registry",
                        "T1601": "Modify System Image", "T1599": "Network Boundary Bridging",
                        "T1027": "Obfuscated Files or Information", "T1647": "Plist File Modification",
                        "T1620": "Reflective Code Loading", "T1207": "Rogue Domain Controller", "T1014": "Rootkit",
                        "T1553": "Subvert Trust Controls", "T1218": "System Binary Proxy Execution",
                        "T1216": "System Script Proxy Execution", "T1221": "Template Injection",
                        "T1127": "Trusted Developer Utilities Proxy Execution",
                        "T1535": "Unused/Unsupported Cloud Regions", "T1550": "Use Alternate Authentication Material",
                        "T1497": "Virtualization/Sandbox Evasion", "T1600": "Weaken Encryption",
                        "T1220": "XSL Script Processing", "T1557": "Adversary-in-the-Middle", "T1110": "Brute Force",
                        "T1555": "Credentials from Password Stores", "T1212": "Exploitation for Credential Access",
                        "T1187": "Forced Authentication", "T1606": "Forge Web Credentials", "T1056": "Input Capture",
                        "T1111": "Multi-Factor Authentication Interception",
                        "T1621": "Multi-Factor Authentication Request Generation", "T1040": "Network Sniffing",
                        "T1003": "OS Credential Dumping", "T1528": "Steal Application Access Token",
                        "T1649": "Steal or Forge Authentication Certificates",
                        "T1558": "Steal or Forge Kerberos Tickets", "T1539": "Steal Web Session Cookie",
                        "T1552": "Unsecured Credentials", "T1087": "Account Discovery",
                        "T1010": "Application Window Discovery", "T1217": "Browser Information Discovery",
                        "T1580": "Cloud Infrastructure Discovery", "T1538": "Cloud Service Dashboard",
                        "T1526": "Cloud Service Discovery", "T1619": "Cloud Storage Object Discovery",
                        "T1613": "Container and Resource Discovery", "T1652": "Device Driver Discovery",
                        "T1482": "Domain Trust Discovery", "T1083": "File and Directory Discovery",
                        "T1615": "Group Policy Discovery", "T1654": "Log Enumeration",
                        "T1046": "Network Service Discovery", "T1135": "Network Share Discovery",
                        "T1201": "Password Policy Discovery", "T1120": "Peripheral Device Discovery",
                        "T1069": "Permission Groups Discovery", "T1057": "Process Discovery", "T1012": "Query Registry",
                        "T1018": "Remote System Discovery", "T1518": "Software Discovery",
                        "T1082": "System Information Discovery", "T1614": "System Location Discovery",
                        "T1016": "System Network Configuration Discovery",
                        "T1049": "System Network Connections Discovery", "T1033": "System Owner/User Discovery",
                        "T1007": "System Service Discovery", "T1124": "System Time Discovery",
                        "T1210": "Exploitation of Remote Services", "T1534": "Internal Spearphishing",
                        "T1570": "Lateral Tool Transfer", "T1563": "Remote Service Session Hijacking",
                        "T1021": "Remote Services", "T1080": "Taint Shared Content", "T1560": "Archive Collected Data",
                        "T1123": "Audio Capture", "T1119": "Automated Collection", "T1185": "Browser Session Hijacking",
                        "T1115": "Clipboard Data", "T1530": "Data from Cloud Storage",
                        "T1602": "Data from Configuration Repository", "T1213": "Data from Information Repositories",
                        "T1005": "Data from Local System", "T1039": "Data from Network Shared Drive",
                        "T1025": "Data from Removable Media", "T1074": "Data Staged", "T1114": "Email Collection",
                        "T1113": "Screen Capture", "T1125": "Video Capture", "T1071": "Application Layer Protocol",
                        "T1092": "Communication Through Removable Media", "T1132": "Data Encoding",
                        "T1001": "Data Obfuscation", "T1568": "Dynamic Resolution", "T1573": "Encrypted Channel",
                        "T1008": "Fallback Channels", "T1105": "Ingress Tool Transfer", "T1104": "Multi-Stage Channels",
                        "T1095": "Non-Application Layer Protocol", "T1571": "Non-Standard Port",
                        "T1572": "Protocol Tunneling", "T1090": "Proxy", "T1219": "Remote Access Software",
                        "T1102": "Web Service", "T1020": "Automated Exfiltration", "T1030": "Data Transfer Size Limits",
                        "T1048": "Exfiltration Over Alternative Protocol", "T1041": "Exfiltration Over C2 Channel",
                        "T1011": "Exfiltration Over Other Network Medium", "T1052": "Exfiltration Over Physical Medium",
                        "T1567": "Exfiltration Over Web Service", "T1029": "Scheduled Transfer",
                        "T1537": "Transfer Data to Cloud Account", "T1531": "Account Access Removal",
                        "T1485": "Data Destruction", "T1486": "Data Encrypted for Impact", "T1565": "Data Manipulation",
                        "T1491": "Defacement", "T1561": "Disk Wipe", "T1499": "Endpoint Denial of Service",
                        "T1657": "Financial Theft", "T1495": "Firmware Corruption", "T1490": "Inhibit System Recovery",
                        "T1498": "Network Denial of Service", "T1496": "Resource Hijacking", "T1489": "Service Stop",
                        "T1529": "System Shutdown/Reboot"}

technique_id_to_subtechniques = {"T1595": {"001": "Scanning IP Blocks", "002": "Vulnerability Scanning", "003": "Wordlist Scanning"},
                                 "T1592": {"001": "Hardware", "002": "Software", "003": "Firmware", "004": "Client Configurations"},
                                 "T1589": {"001": "Credentials", "002": "Email Addresses", "003": "Employee Names"},
                                 "T1590": {"001": "Domain Properties", "002": "DNS", "003": "Network Trust Dependencies", "004": "Network Topology", "005": "IP Addresses", "006": "Network Security Appliances"},
                                 "T1591": {"001": "Determine Physical Locations", "002": "Business Relationships", "003": "Identify Business Tempo", "004": "Identify Roles"},
                                 "T1598": {"001": "Spearphishing Service", "002": "Spearphishing Attachment", "003": "Spearphishing Link", "004": "Spearphishing Voice"},
                                 "T1597": {"001": "Threat Intel Vendors", "002": "Purchase Technical Data"},
                                 "T1596": {"001": "DNS/Passive DNS", "002": "WHOIS", "003": "Digital Certificates", "004": "CDNs", "005": "Scan Databases"},
                                 "T1593": {"001": "Social Media", "002": "Search Engines", "003": "Code Repositories"},
                                 "T1583": {"001": "Domains", "002": "DNS Server", "003": "Virtual Private Server", "004": "Server", "005": "Botnet", "006": "Web Services", "007": "Serverless", "008": "Malvertising"},
                                 "T1586": {"001": "Social Media Accounts", "002": "Email Accounts", "003": "Cloud Accounts"},
                                 "T1584": {"001": "Domains", "002": "DNS Server", "003": "Virtual Private Server", "004": "Server", "005": "Botnet", "006": "Web Services", "007": "Serverless"},
                                 "T1587": {"001": "Malware", "002": "Code Signing Certificates", "003": "Digital Certificates", "004": "Exploits"},
                                 "T1585": {"001": "Social Media Accounts", "002": "Email Accounts", "003": "Cloud Accounts"},
                                 "T1588": {"001": "Malware", "002": "Tool", "003": "Code Signing Certificates", "004": "Digital Certificates", "005": "Exploits", "006": "Vulnerabilities"},
                                 "T1608": {"001": "Upload Malware", "002": "Upload Tool", "003": "Install Digital Certificate", "004": "Drive-by Target", "005": "Link Target", "006": "SEO Poisoning"},
                                 "T1566": {"001": "Spearphishing Attachment", "002": "Spearphishing Link", "003": "Spearphishing via Service", "004": "Spearphishing Voice"},
                                 "T1195": {"001": "Compromise Software Dependencies and Development Tools", "002": "Compromise Software Supply Chain", "003": "Compromise Hardware Supply Chain"},
                                 "T1078": {"001": "Default Accounts", "002": "Domain Accounts", "003": "Local Accounts", "004": "Cloud Accounts"},
                                 "T1059": {"001": "PowerShell", "002": "AppleScript", "003": "Windows Command Shell", "004": "Unix Shell", "005": "Visual Basic", "006": "Python", "007": "JavaScript", "008": "Network Device CLI", "009": "Cloud API"},
                                 "T1559": {"001": "Component Object Model", "002": "Dynamic Data Exchange", "003": "XPC Services"},
                                 "T1053": {"001": "At", "002": "Cron", "003": "Scheduled Task", "004": "Systemd Timers", "005": "Container Orchestration Job"},
                                 "T1569": {"001": "Launchctl", "002": "Service Execution"},
                                 "T1204": {"001": "Malicious Link", "002": "Malicious File", "003": "Malicious Image"},
                                 "T1098": {"001": "Additional Cloud Credentials", "002": "Additional Email Delegate Permissions", "003": "Additional Cloud Roles", "004": "SSH Authorized Keys", "005": "Device Registration", "006": "Additional Container Cluster Roles"},
                                 "T1547": {"001": "Registry Run Keys / Startup Folder", "002": "Authentication Package", "003": "Time Providers", "004": "Winlogon Helper DLL", "005": "Security Support Provider", "006": "Kernel Modules and Extensions", "007": "Re-opened Applications", "008": "LSASS Driver", "009": "Shortcut Modification", "010": "Port Monitors", "011": "Print Processors", "012": "XDG Autostart Entries", "013": "Active Setup", "014": "Login Items"},
                                 "T1037": {"001": "Logon Script (Windows)", "002": "Login Hook", "003": "Network Logon Script", "004": "RC Scripts", "005": "Startup Items"},
                                 "T1136": {"001": "Local Account", "002": "Domain Account", "003": "Cloud Account"},
                                 "T1543": {"001": "Launch Agent", "002": "Systemd Service", "003": "Windows Service", "004": "Launch Daemon"},
                                 "T1546": {"001": "Change Default File Association", "002": "Screensaver", "003": "Windows Management Instrumentation Event Subscription", "004": "Unix Shell Configuration Modification", "005": "Trap", "006": "LC_LOAD_DYLIB Addition", "007": "Netsh Helper DLL", "008": "Accessibility Features", "009": "AppCert DLLs", "010": "AppInit DLLs", "011": "Application Shimming", "012": "Image File Execution Options Injection", "013": "PowerShell Profile", "014": "Emond", "015": "Component Object Model Hijacking", "016": "Installer Packages"},
                                 "T1574": {"001": "DLL Search Order Hijacking", "002": "DLL Side-Loading", "003": "Dylib Hijacking", "004": "Executable Installer File Permissions Weakness", "005": "Dynamic Linker Hijacking", "006": "Path Interception by PATH Environment Variable", "007": "Path Interception by Search Order Hijacking", "008": "Path Interception by Unquoted Path", "009": "Services File Permissions Weakness", "010": "Services Registry Permissions Weakness", "011": "COR_PROFILER", "012": "KernelCallbackTable"},
                                 "T1556": {"001": "Domain Controller Authentication", "002": "Password Filter DLL", "003": "Pluggable Authentication Modules", "004": "Network Device Authentication", "005": "Reversible Encryption", "006": "Multi-Factor Authentication", "007": "Hybrid Identity", "008": "Network Provider DLL"},
                                 "T1137": {"001": "Office Template Macros", "002": "Office Test", "003": "Outlook Forms", "004": "Outlook Home Page", "005": "Outlook Rules", "006": "Add-ins"},
                                 "T1542": {"001": "System Firmware", "002": "Component Firmware", "003": "Bootkit", "004": "ROMMONkit", "005": "TFTP Boot"},
                                 "T1505": {"001": "SQL Stored Procedures", "002": "Transport Agent", "003": "Web Shell", "004": "IIS Components", "005": "Terminal Services DLL"},
                                 "T1205": {"001": "Port Knocking", "002": "Socket Filters"},
                                 "T1548": {"001": "Setuid and Setgid", "002": "Bypass User Account Control", "003": "Sudo and Sudo Caching", "004": "Elevated Execution with Prompt", "005": "Temporary Elevated Cloud Access"},
                                 "T1134": {"001": "Token Impersonation/Theft", "002": "Create Process with Token", "003": "Make and Impersonate Token", "004": "Parent PID Spoofing", "005": "SID-History Injection"},
                                 "T1484": {"001": "Group Policy Modification", "002": "Domain Trust Modification"},
                                 "T1055": {"001": "", "002": "", "003": "", "004": "", "005": "", "006": "", "007": "", "008": "", "009": "", "010": "", "011": "", "012": ""},
                                 "T1480": {"001": "Environmental Keying"},
                                 "T1222": {"001": "Windows File and Directory Permissions Modification", "002": "Linux and Mac File and Directory Permissions Modification"},
                                 "T1564": {"001": "Hidden Files and Directories", "002": "Hidden Users", "003": "Hidden Window", "004": "NTFS File Attributes", "005": "Hidden File System", "006": "Run Virtual Instance", "007": "VBA Stomping", "008": "Email Hiding Rules", "009": "Resource Forking", "010": "Process Argument Spoofing", "011": "Ignore Process Interrupts"},
                                 "T1562": {"001": "Disable or Modify Tools", "002": "Disable Windows Event Logging", "003": "Impair Command History Logging", "004": "Disable or Modify System Firewall", "005": "Indicator Blocking", "006": "Disable or Modify Cloud Firewall", "007": "Disable or Modify Cloud Logs", "008": "Safe Mode Boot", "009": "Downgrade Attack", "010": "Spoof Security Alerting", "011": "Disable or Modify Linux Audit System"},
                                 "T1070": {"001": "Clear Windows Event Logs", "002": "Clear Linux or Mac System Logs", "003": "Clear Command History", "004": "File Deletion", "005": "Network Share Connection Removal", "006": "Timestomp", "007": "Clear Network Connection History and Configurations", "008": "Clear Mailbox Data", "009": "Clear Persistence"},
                                 "T1036": {"001": "Invalid Code Signature", "002": "Right-to-Left Override", "003": "Rename System Utilities", "004": "Masquerade Task or Service", "005": "Match Legitimate Name or Location", "006": "Space after Filename", "007": "Double File Extension", "008": "Masquerade File Type", "009": "Break Process Trees"},
                                 "T1578": {"001": "Create Snapshot", "002": "Create Cloud Instance", "003": "Delete Cloud Instance", "004": "Revert Cloud Instance", "005": "Modify Cloud Compute Configurations"},
                                 "T1601": {"001": "Patch System Image", "002": "Downgrade System Image"},
                                 "T1599": {"001": "Network Address Translation Traversal"},
                                 "T1027": {"001": "Binary Padding", "002": "Software Packing", "003": "Steganography", "004": "Compile After Delivery", "005": "Indicator Removal from Tools", "006": "HTML Smuggling", "007": "Dynamic API Resolution", "008": "Stripped Payloads", "009": "Embedded Payloads", "010": "Command Obfuscation", "011": "Fileless Storage", "012": "LNK Icon Smuggling"},
                                 "T1553": {"001": "Gatekeeper Bypass", "002": "Code Signing", "003": "SIP and Trust Provider Hijacking", "004": "Install Root Certificate", "005": "Mark-of-the-Web Bypass", "006": "Code Signing Policy Modification"},
                                 "T1218": {"001": "Compiled HTML File", "002": "Control Panel", "003": "CMSTP", "004": "InstallUtil", "005": "Mshta", "006": "Msiexec", "007": "Odbcconf", "008": "Regsvcs/Regasm", "009": "Regsvr32", "010": "Rundll32", "011": "Verclsid", "012": "Mavinject", "013": "MMC"},
                                 "T1216": {"001": "PubPrn"},
                                 "T1127": {"001": "MSBuild"},
                                 "T1550": {"001": "Application Access Token", "002": "Pass the Hash", "003": "Pass the Ticket", "004": "Web Session Cookie"},
                                 "T1497": {"001": "System Checks", "002": "User Activity Based Checks", "003": "Time Based Evasion"},
                                 "T1600": {"001": "Reduce Key Space", "002": "Disable Crypto Hardware"},
                                 "T1557": {"001": "LLMNR/NBT-NS Poisoning and SMB Relay", "002": "ARP Cache Poisoning", "003": "DHCP Spoofing"},
                                 "T1110": {"001": "Password Guessing", "002": "Password Cracking", "003": "Password Spraying", "004": "Credential Stuffing"},
                                 "T1555": {"001": "Keychain", "002": "Securityd Memory", "003": "Credentials from Web Browsers", "004": "Windows Credential Manager", "005": "Password Managers", "006": "Cloud Secrets Management Stores"},
                                 "T1606": {"001": "Web Cookies", "002": "SAML Tokens"},
                                 "T1056": {"001": "Keylogging", "002": "GUI Input Capture", "003": "Web Portal Capture", "004": "Credential API Hooking"},
                                 "T1003": {"001": "LSASS Memory", "002": "Security Account Manager", "003": "NTDS", "004": "LSA Secrets", "005": "Cached Domain Credentials", "006": "DCSync", "007": "Proc Filesystem", "008": "/etc/passwd and /etc/shadow"},
                                 "T1558": {"001": "Golden Ticket", "002": "Silver Ticket", "003": "Kerberoasting", "004": "AS-REP Roasting"},
                                 "T1552": {"001": "Credentials In Files", "002": "Credentials in Registry", "003": "Bash History", "004": "Private Keys", "005": "Cloud Instance Metadata API", "006": "Group Policy Preferences", "007": "Container API", "008": "Chat Messages"},
                                 "T1087": {"001": "Local Account", "002": "Domain Account", "003": "Email Account", "004": "Cloud Account"},
                                 "T1069": {"001": "Local Groups", "002": "Domain Groups", "003": "Cloud Groups"},
                                 "T1518": {"001": "Security Software Discovery"},
                                 "T1614": {"001": "System Language Discovery"},
                                 "T1016": {"001": "Internet Connection Discovery", "002": "Wi-Fi Discovery"},
                                 "T1563": {"001": "SSH Hijacking", "002": "RDP Hijacking"},
                                 "T1021": {"001": "Remote Desktop Protocol", "002": "SMB/Windows Admin Shares", "003": "Distributed Component Object Model", "004": "SSH", "005": "VNC", "006": "Windows Remote Management", "007": "Cloud Services", "008": "Direct Cloud VM Connections"},
                                 "T1560": {"001": "Archive via Utility", "002": "Archive via Library", "003": "Archive via Custom Method"},
                                 "T1602": {"001": "SNMP (MIB Dump)", "002": "Network Device Configuration Dump"},
                                 "T1213": {"001": "Confluence", "002": "Sharepoint", "003": "Code Repositories"},
                                 "T1074": {"001": "Local Data Staging", "002": "Remote Data Staging"},
                                 "T1114": {"001": "Local Email Collection", "002": "Remote Email Collection", "003": "Email Forwarding Rule"},
                                 "T1071": {"001": "Web Protocols", "002": "File Transfer Protocols", "003": "Mail Protocols", "004": "DNS"},
                                 "T1132": {"001": "Standard Encoding", "002": "Non-Standard Encoding"},
                                 "T1001": {"001": "Junk Data", "002": "Steganography", "003": "Protocol Impersonation"},
                                 "T1568": {"001": "Fast Flux DNS", "002": "Domain Generation Algorithms", "003": "DNS Calculation"},
                                 "T1573": {"001": "Symmetric Cryptography", "002": "Asymmetric Cryptography"},
                                 "T1090": {"001": "Internal Proxy", "002": "External Proxy", "003": "Multi-hop Proxy", "004": "Domain Fronting"},
                                 "T1102": {"001": "Dead Drop Resolver", "002": "Bidirectional Communication", "003": "One-Way Communication"},
                                 "T1020": {"001": "Traffic Duplication"},
                                 "T1048": {"001": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "002": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "003": "Exfiltration Over Unencrypted Non-C2 Protocol"},
                                 "T1011": {"001": "Exfiltration Over Bluetooth"},
                                 "T1052": {"001": "Exfiltration over USB"},
                                 "T1567": {"001": "Exfiltration to Code Repository", "002": "Exfiltration to Cloud Storage", "003": "Exfiltration to Text Storage Sites", "004": "Exfiltration Over Webhook"},
                                 "T1565": {"001": "Stored Data Manipulation", "002": "Transmitted Data Manipulation", "003": "Runtime Data Manipulation"},
                                 "T1491": {"001": "Internal Defacement", "002": "External Defacement"},
                                 "T1561": {"001": "Disk Content Wipe", "002": "Disk Structure Wipe"},
                                 "T1499": {"001": "OS Exhaustion Flood", "002": "Service Exhaustion Flood", "003": "Application Exhaustion Flood", "004": "Application or System Exploitation"},
                                 "T1498": {"001": "Direct Network Flood", "002": "Reflection Amplification"}}


# def print_entities(rule_objects_list: list[dict]):
#     def add_detection_entities_rec(rule_object: dict, api_calls: list[str], iocs: list[str], others: list[str]):
#         for key, value in rule_object.items():
#             key = key.split("|")[0]
#             if key == "condition":
#                 continue
#             if isinstance(value, str) or isinstance(value, int):
#                 if key == "eventName":
#                     if value not in api_calls:
#                         api_calls.append(value)
#                 elif key == "sourceIPAddress" or key == "userAgent":
#                     if value not in iocs:
#                         iocs.append(value)
#                 else:
#                     if value not in others:
#                         others.append(value)
#             elif isinstance(value, list):
#                 for item in value:
#                     if key == "eventName":
#                         if item not in api_calls:
#                             api_calls.append(item)
#                     elif key == "sourceIPAddress" or key == "userAgent":
#                         if item not in iocs:
#                             iocs.append(item)
#                     else:
#                         if item not in others:
#                             others.append(item)
#             elif isinstance(value, dict):
#                 add_detection_entities_rec(value, api_calls, iocs, others)
#
#     api_calls, tactics, techniques, sub_techniques, iocs, others = [], [], [], [], [], []
#     for rule_object in rule_objects_list:
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if not tag.startswith("t"):
#                 tag = tag.replace("_", " ").replace("-", " ").title()
#                 if tag not in tactic_name_to_id:
#                     continue
#                 tag = f"{tag} ({tactic_name_to_id[tag]})"
#                 if tag not in tactics:
#                     tactics.append(tag)
#             elif "." not in tag:
#                 tag = tag.upper()
#                 if tag not in technique_id_to_name:
#                     continue
#                 tag = f"{technique_id_to_name[tag]} ({tag})"
#                 if tag not in techniques:
#                     techniques.append(tag)
#             else:
#                 tag = tag.upper()
#                 technique, sub_technique = tag.split(".")
#                 if technique not in technique_id_to_subtechniques:
#                     continue
#                 if sub_technique not in technique_id_to_subtechniques[technique]:
#                     continue
#                 tag = f"{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})"
#                 if tag not in sub_techniques:
#                     sub_techniques.append(tag)
#         add_detection_entities_rec(rule_object["detection"], api_calls, iocs, others)
#     print("API Call:")
#     for api_call in api_calls:
#         print(api_call)
#     print("\nTactic:")
#     for tactic in tactics:
#         print(tactic)
#     print("\nTechnique:")
#     for technique in techniques:
#         print(technique)
#     print("\nSub-techniques:")
#     for sub_technique in sub_techniques:
#         print(sub_technique)
#     print("\nIoC:")
#     for ioc in iocs:
#         print(ioc)
#     print("\nOther:")
#     for other in others:
#         print(other)
#
#
# def print_entity_sigma_field(rule_objects_list: list[dict]):
#     def add_entity_sigma_field_rec(rule_object: dict, results: list[str]):
#         for key, value in rule_object.items():
#             key = key.split("|")[0]
#             if key == "condition":
#                 continue
#             if isinstance(value, str):
#                 if f"{value} ↔ {key}" not in results:
#                     results.add(f"{value} ↔ {key}")
#             elif isinstance(value, list):
#                 for item in value:
#                     if f"{item} ↔ {key}" not in results:
#                         results.add(f"{item} ↔ {key}")
#             elif isinstance(value, dict):
#                 add_entity_sigma_field_rec(value, results)
#
#     non_ttp_entitites = set()
#     ttp_entitites = set()
#     for rule_object in rule_objects_list:
#         for tag in rule_object["tags"]:
#             tag = tag.replace("attack.", "")
#             tag = tag.replace("_", " ")
#             tag = tag.title()
#             if tag in tactic_name_to_id:
#                 tag = f"{tag} ({tactic_name_to_id[tag]})"
#             if tag in technique_id_to_name:
#                 tag = f"{technique_id_to_name[tag]} ({tag})"
#             if len(tag) == 9 and tag[0] == 'T' and tag[1:5].isdigit() and tag[5] == "." and tag[6:].isdigit():
#                 technique, sub_technique = tag.split(".")
#                 if technique not in technique_id_to_subtechniques:
#                     continue
#                 if sub_technique not in technique_id_to_subtechniques[technique]:
#                     continue
#                 tag = f"{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})"
#             ttp_entitites.add(f"{tag} ↔ tags")
#         add_entity_sigma_field_rec(rule_object["detection"], non_ttp_entitites)
#     print("\nEntity ↔ Sigma Field:")
#     for non_ttp_entity in non_ttp_entitites:
#         print(non_ttp_entity)
#     print("\nTTP ↔ Sigma Field:")
#     for ttp_entity in ttp_entitites:
#         print(ttp_entity)
#
#
# def add_api_call_rec(rule_object: dict, api_calls: list[str]):
#     for key, value in rule_object.items():
#         key = key.split("|")[0]
#         if key == "condition":
#             continue
#         if isinstance(value, str):
#             if key == "eventName":
#                 if value not in api_calls:
#                     api_calls.append(value)
#         elif isinstance(value, list):
#             for item in value:
#                 if key == "eventName":
#                     if item not in api_calls:
#                         api_calls.append(item)
#         elif isinstance(value, dict):
#             add_api_call_rec(value, api_calls)
#
#
# def add_ioc_rec(rule_object: dict, iocs: list[str]):
#     for key, value in rule_object.items():
#         key = key.split("|")[0]
#         if key == "condition":
#             continue
#         if isinstance(value, str):
#             if key == "sourceIPAddress" or key == "userAgent":
#                 if value not in iocs:
#                     iocs.append(value)
#         elif isinstance(value, list):
#             for item in value:
#                 if key == "sourceIPAddress" or key == "userAgent":
#                     if item not in iocs:
#                         iocs.append(item)
#         elif isinstance(value, dict):
#             add_ioc_rec(value, iocs)
#
#
# def print_api_call_tactic(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Tactic:")
#     for rule_object in rule_objects_list:
#         tactics = []
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if not tag.startswith("t"):
#                 tag = tag.replace("_", " ").replace("-", " ").title()
#                 if tag not in tactic_name_to_id:
#                     continue
#                 tag = f"{tag} ({tactic_name_to_id[tag]})"
#                 if tag not in tactics:
#                     tactics.append(tag)
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         for api_call in api_calls:
#             for tactic in tactics:
#                 print(f"{api_call} ↔ {tactic}")
#
#
# def print_api_call_technique(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Technique:")
#     for rule_object in rule_objects_list:
#         techniques = []
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if tag[0] == 't' and tag[1:].isdigit():
#                 tag = tag.upper()
#                 if tag not in technique_id_to_name:
#                     continue
#                 tag = f"{technique_id_to_name[tag]} ({tag})"
#                 if tag not in techniques:
#                     techniques.append(tag)
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         for api_call in api_calls:
#             for technique in techniques:
#                 print(f"{api_call} ↔ {technique}")
#
#
# def print_api_call_sub_technique(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Sub-technique:")
#     for rule_object in rule_objects_list:
#         sub_techniques = []
#         for tag in rule_object["tags"]:
#             tag = tag.lower().replace("attack.", "")
#             if len(tag) == 9 and tag[0] == 't' and tag[1:5].isdigit() and tag[5] == "." and tag[6:].isdigit():
#                 tag = tag.upper()
#                 technique, sub_technique = tag.split(".")
#                 if technique not in technique_id_to_subtechniques:
#                     continue
#                 if sub_technique not in technique_id_to_subtechniques[technique]:
#                     continue
#                 tag = f"{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})"
#                 if tag not in sub_techniques:
#                     sub_techniques.append(tag)
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         for api_call in api_calls:
#             for sub_technique in sub_techniques:
#                 print(f"{api_call} ↔ {sub_technique}")
#
#
# def print_api_call_ioc(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ IoC:")
#     for rule_object in rule_objects_list:
#         api_calls = []
#         add_api_call_rec(rule_object["detection"], api_calls)
#         iocs = []
#         add_ioc_rec(rule_object["detection"], iocs)
#         for api_call in api_calls:
#             for ioc in iocs:
#                 print(f"{api_call} ↔ {ioc}")
#
#
# def print_api_call_other(rule_objects_list: list[dict]):
#     print("\nAPI Call ↔ Other:")
#     def add_other_rec(rule_object: dict, others: list[str]):
#         for key, value in rule_object.items():
#             key = key.split("|")[0]
#             if isinstance(value, str) or isinstance(value, int):
#                 if key != "eventName" and key != "sourceIPAddress" and key != "userAgent":
#                     if value not in others:
#                         others.append(value)
#             elif isinstance(value, list):
#                 for item in value:
#                     if key != "eventName" and key != "sourceIPAddress" and key != "userAgent":
#                         if item not in others:
#                             others.append(item)
#             elif isinstance(value, dict):
#                 add_ioc_rec(value, others)
#
#     for rule_object in rule_objects_list:
#         for key, value in rule_object["detection"].items():
#             key = key.split("|")[0]
#             if key == "condition":
#                 continue
#             api_calls = []
#             add_api_call_rec(value, api_calls)
#             others = []
#             add_other_rec(value, others)
#             for api_call in api_calls:
#                 for other in others:
#                     print(f"{api_call} ↔ {other}")
#
#
# def get_text_similarity(text1: str, text2: str) -> float:
#     # from dotenv import load_dotenv
#     # import os
#     # from openai import OpenAI
#     # from sklearn.metrics.pairwise import cosine_similarity
#     #
#     # load_dotenv()
#     # client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
#     # sentence1 = "The capital of France is Paris"
#     # sentence2 = "Paris is the capital of France"
#     # embedding1 = client.embeddings.create(input=[sentence1], model="text-embedding-3-large").data[0].embedding
#     # embedding2 = client.embeddings.create(input=[sentence2], model="text-embedding-3-large").data[0].embedding
#     # return cosine_similarity([embedding1], [embedding2])[0][0]
#     model = SentenceTransformer('Lajavaness/bilingual-embedding-large', trust_remote_code=True)
#     embeddings = model.encode([text1, text2])
#     similarities = model.similarity(embeddings, embeddings)
#
#     return similarities[0][1].item()


def get_ttps(tags: list[str]) -> tuple[set[str], set[str], set[str]]:
    tactics, techniques, subtechniques = set(), set(), set()

    for tag in tags:
        tag = tag.lower().replace('attack.', '')
        if not tag.startswith('t'):
            tag = tag.replace('_', ' ').replace('-', ' ').title()
            if tag in tactic_name_to_id:
                tactics.add(f'{tag} ({tactic_name_to_id[tag]})')
        elif '.' not in tag:
            tag = tag.upper()
            if tag in technique_id_to_name:
                techniques.add(f'{technique_id_to_name[tag]} ({tag})')
        else:
            tag = tag.upper()
            technique, sub_technique = tag.split('.')
            if technique in technique_id_to_subtechniques and sub_technique in technique_id_to_subtechniques[technique]:
                techniques.add(f'{technique_id_to_name[technique]} ({technique})')
                subtechniques.add(f'{technique_id_to_name[technique]}: {technique_id_to_subtechniques[technique][sub_technique]} ({tag})')

    return tactics, techniques, subtechniques


def extract_logsource_data(logsource: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    product_field_names, service_field_names = set(), set()
    products, services = set(), set()
    product_field_names_and_products, service_field_names_and_services = set(), set()

    for key, value in logsource.items():
        if key == 'product':
            add_to_sets(key, value, product_field_names, products, product_field_names_and_products)
        elif key == 'service':
            add_to_sets(key, value, service_field_names, services, service_field_names_and_services)

    return product_field_names, service_field_names, products, services, product_field_names_and_products, service_field_names_and_services


# def match_special_string(special_string: str, candidate: str) -> bool:
#     # Convert special string to regex
#     pattern = re.escape(special_string).replace(r'\*', '.*')
#     # Add start and end anchors to ensure full string match
#     pattern = f'^{pattern}$'
#     # Check if candidate matches the pattern
#     return re.match(pattern, candidate) is not None
#
#
# def calculate_performance_metrics(ground_truth_data: Set[str], output_data: Set[str]) -> Tuple[int, Tuple[float, float, float]]:
#     support = len(ground_truth_data)
#
#     TP = 0
#     FN = 0
#
#     # Mark which items have been matched
#     matched_output = set()
#
#     # Calculate TP and FN
#     for ground_truth_item in ground_truth_data:
#         match_found = False
#         for output_item in output_data:
#             if match_special_string(ground_truth_item, output_item) or match_special_string(output_item, ground_truth_item):
#                 TP += 1
#                 matched_output.add(output_item)
#                 match_found = True
#                 break
#         if not match_found:
#             FN += 1
#
#     # Calculate FP (output items that were not matched with ground truth)
#     FP = len(output_data - matched_output)
#
#     precision = TP / (TP + FP) if (TP + FP) > 0 else 0
#     recall = TP / (TP + FN) if (TP + FN) > 0 else 0
#     f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
#
#     return support, (precision, recall, f1_score)


def add_to_sets(key: str, value: str | list[str], keys_set: set[str], values_set: set[str], keys_and_values_set: set[tuple[str, str]]) -> None:
    if key.endswith('|contains'):
        key = key[:-9]
        prefix, suffix = '*', '*'
    elif key.endswith('|startswith'):
        key = key[:-10]
        prefix, suffix = '', '*'
    elif key.endswith('|endswith'):
        key = key[:-8]
        prefix, suffix = '*', ''
    else:
        prefix, suffix = '', ''

    keys_set.add(key)

    if isinstance(value, str):
        values_set.add(f'{prefix}{value}{suffix}')
        keys_and_values_set.add((key, f'{prefix}{value}{suffix}'))
    elif isinstance(value, list):
        values_set.update({f'{prefix}{item}{suffix}' for item in value})
        keys_and_values_set.update((key, f'{prefix}{item}{suffix}') for item in value)


def extract_apis(detection: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    api_name_field_names, api_source_field_names = set(), set()
    api_names, api_sources = set(), set()
    api_name_field_names_and_api_names, api_source_field_names_and_api_sources = set(), set()

    for key, value in detection.items():
        if isinstance(value, dict):
            api_name_field_names_rec, api_source_field_names_rec, api_names_rec, api_sources_rec, api_name_field_names_and_api_names_rec, api_source_field_names_and_api_sources_rec = extract_apis(value)
            api_name_field_names.update(api_name_field_names_rec)
            api_source_field_names.update(api_source_field_names_rec)
            api_names.update(api_names_rec)
            api_sources.update(api_sources_rec)
            api_name_field_names_and_api_names.update(api_name_field_names_and_api_names_rec)
            api_source_field_names_and_api_sources.update(api_source_field_names_and_api_sources_rec)
            # recursive_events, recursive_sources = extract_apis(value)
            # api_names.update(recursive_events)
            # api_sources.update(recursive_sources)
        elif key.startswith('eventName'):
            add_to_sets(key, value, api_name_field_names, api_names, api_name_field_names_and_api_names)
        elif key.startswith('eventSource'):
            add_to_sets(key, value, api_source_field_names, api_sources, api_source_field_names_and_api_sources)
        # elif key.startswith('eventName') or key.startswith('eventSource'):
        #     relevant_set = api_names if key.startswith('eventName') else api_sources
        #     add_to_sets(key, value, relevant_set)

    # return api_names, api_sources
    return api_name_field_names, api_source_field_names, api_names, api_sources, api_name_field_names_and_api_names, api_source_field_names_and_api_sources


def extract_ioc(detection: dict) -> tuple[set[str], set[str], set[str], set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    ip_address_field_names, user_agent_field_names = set(), set()
    ip_addresses, user_agents = set(), set()
    ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents = set(), set()
    # ioc = set()

    for key, value in detection.items():
        if isinstance(value, dict):
            ip_address_field_names_rec, user_agent_field_names_rec, ip_addresses_rec, user_agents_rec, ip_address_field_names_and_ip_addresses_rec, user_agent_field_names_and_user_agents_rec = extract_ioc(value)
            ip_address_field_names.update(ip_address_field_names_rec)
            user_agent_field_names.update(user_agent_field_names_rec)
            ip_addresses.update(ip_addresses_rec)
            user_agents.update(user_agents_rec)
            ip_address_field_names_and_ip_addresses.update(ip_address_field_names_and_ip_addresses_rec)
            user_agent_field_names_and_user_agents.update(user_agent_field_names_and_user_agents_rec)
            # ioc.update(get_ioc(value))
        elif key.startswith('sourceIPAddress'):
            add_to_sets(key, value, ip_address_field_names, ip_addresses, ip_address_field_names_and_ip_addresses)
        elif key.startswith('userAgent'):
            add_to_sets(key, value, user_agent_field_names, user_agents, user_agent_field_names_and_user_agents)
        # elif key.startswith('sourceIPAddress') or key.startswith('userAgent'):
        #     add_to_sets(key, value, ioc)

    # return ioc
    return ip_address_field_names, user_agent_field_names, ip_addresses, user_agents, ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents


def extract_others(detection: dict) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    other_field_names = set()
    others = set()
    other_field_names_and_others = set()

    for key, value in detection.items():
        if isinstance(value, dict):
            other_field_names_rec, others_rec, other_field_names_and_others_rec = extract_others(value)
            other_field_names.update(other_field_names_rec)
            others.update(others_rec)
            other_field_names_and_others.update(other_field_names_and_others_rec)
            # others.update(get_others(value))
        elif not key.startswith('eventName') and not key.startswith('eventSource') and not key.startswith('sourceIPAddress') and not key.startswith('userAgent') and not key.startswith('condition'):
            add_to_sets(key, value, other_field_names, others, other_field_names_and_others)
            # add_to_sets(key, value, others)

    # return others
    return other_field_names, others, other_field_names_and_others


# def compare_sigma_rules(ground_truth_rule: Dict, output_rule: Dict):
#     results = {}
#
#     # results["title_similarity"] = get_text_similarity(ground_truth_rule["title"], output_rule["title"])
#     # results["description_similarity"] = get_text_similarity(ground_truth_rule["description"], output_rule["description"])
#
#     ground_truth_tactics, ground_truth_techniques, ground_truth_subtechniques = get_ttps(ground_truth_rule['tags'])
#     output_tactics, output_techniques, output_subtechniques = get_ttps(output_rule['tags'])
#     results['tactic'], results['technique'], results['subtechnique'] = calculate_performance_metrics(ground_truth_tactics, output_tactics), calculate_performance_metrics(ground_truth_techniques, output_techniques), calculate_performance_metrics(ground_truth_subtechniques, output_subtechniques)
#
#     ground_truth_product, ground_truth_service = {ground_truth_rule['logsource']['product']}, {ground_truth_rule['logsource']['service']}
#     output_product, output_service = {output_rule['logsource']['product']}, {output_rule['logsource']['service']}
#     results['product'], results['service'] = calculate_performance_metrics(ground_truth_product, output_product), calculate_performance_metrics(ground_truth_service, output_service)
#
#     ground_truth_events, ground_truth_sources = get_api_calls(ground_truth_rule)
#     output_events, output_sources = get_api_calls(output_rule)
#     results['event'], results['source'] = calculate_performance_metrics(ground_truth_events, output_events), calculate_performance_metrics(ground_truth_sources, output_sources)
#
#     ground_truth_ioc = get_ioc(ground_truth_rule['detection'])
#     output_ioc = get_ioc(output_rule['detection'])
#     results['ioc'] = calculate_performance_metrics(ground_truth_ioc, output_ioc)
#
#     ground_truth_others = get_others(ground_truth_rule['detection'])
#     output_others = get_others(output_rule['detection'])
#     results['other'] = calculate_performance_metrics(ground_truth_others, output_others)
#
#     # TODO: Handle 'falsepositives' field
#
#     criticality_levels = {'informational': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
#     ground_truth_criticality = criticality_levels[ground_truth_rule['level']]
#     output_criticality = criticality_levels[output_rule['level']]
#     results['criticality'] = 1 + (output_criticality - ground_truth_criticality) * 0.25
#
#     return results


def extract_entities_and_relationships(rules: dict | list[dict]) -> tuple[dict[str, set[str]], dict[str, set[tuple[str, str]]]]:
    if isinstance(rules, dict):
        rules = [rules]

    entities = {
        'tactics': set(),
        'techniques': set(),
        'subtechniques': set(),
        'product_field_names': set(),
        'service_field_names': set(),
        'products': set(),
        'services': set(),
        'api_name_field_names': set(),
        'api_source_field_names': set(),
        'api_names': set(),
        'api_sources': set(),
        'ip_address_field_names': set(),
        'user_agent_field_names': set(),
        'ip_addresses': set(),
        'user_agents': set(),
        'other_field_names': set(),
        'others': set()
    }
    relationships = {
        'product_field_names_and_products': set(),
        'service_field_names_and_services': set(),
        'api_name_field_names_and_api_names': set(),
        'api_source_field_names_and_api_sources': set(),
        'ip_address_field_names_and_ip_addresses': set(),
        'user_agent_field_names_and_user_agents': set(),
        'other_field_names_and_others': set()
    }
    for rule in rules:
        tactics, techniques, subtechniques = get_ttps(rule['tags'])
        entities['tactics'].update(tactics)
        entities['techniques'].update(techniques)
        entities['subtechniques'].update(subtechniques)

        product_field_names, service_field_names, products, services, product_field_names_and_products, service_field_names_and_services = extract_logsource_data(rule['logsource'])
        entities['product_field_names'].update(product_field_names)
        entities['service_field_names'].update(service_field_names)
        entities['products'].update(products)
        entities['services'].update(services)
        relationships['product_field_names_and_products'].update(product_field_names_and_products)
        relationships['service_field_names_and_services'].update(service_field_names_and_services)

        api_name_field_names, api_source_field_names, api_names, api_sources, api_name_field_names_and_api_names, api_source_field_names_and_api_sources = extract_apis(rule['detection'])
        entities['api_name_field_names'].update(api_name_field_names)
        entities['api_source_field_names'].update(api_source_field_names)
        entities['api_names'].update(api_names)
        entities['api_sources'].update(api_sources)
        relationships['api_name_field_names_and_api_names'].update(api_name_field_names_and_api_names)
        relationships['api_source_field_names_and_api_sources'].update(api_source_field_names_and_api_sources)

        ip_address_field_names, user_agent_field_names, ip_addresses, user_agents, ip_address_field_names_and_ip_addresses, user_agent_field_names_and_user_agents = extract_ioc(rule['detection'])
        entities['ip_address_field_names'].update(ip_address_field_names)
        entities['user_agent_field_names'].update(user_agent_field_names)
        entities['ip_addresses'].update(ip_addresses)
        entities['user_agents'].update(user_agents)
        relationships['ip_address_field_names_and_ip_addresses'].update(ip_address_field_names_and_ip_addresses)
        relationships['user_agent_field_names_and_user_agents'].update(user_agent_field_names_and_user_agents)

        other_field_names, others, other_field_names_and_others = extract_others(rule['detection'])
        entities['other_field_names'].update(other_field_names)
        entities['others'].update(others)
        relationships['other_field_names_and_others'].update(other_field_names_and_others)

    return entities, relationships


def main():
    ground_truth_rule = yaml.safe_load("""title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
id: db014773-7375-4f4e-b83b-133337c0ffee
status: experimental
description: Detects S3 Browser utility creating Inline IAM Policy containing default S3 bucket name placeholder value of <YOUR-BUCKET-NAME>.
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: 2023/05/17
modified: 2023/05/17
tags:
    - attack.execution
    - attack.t1059.009
    - attack.persistence
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: iam.amazonaws.com
        eventName: PutUserPolicy
    filter_tooling:
        userAgent|contains: 'S3 Browser'
    filter_policy_resource:
        requestParameters|contains: '"arn:aws:s3:::<YOUR-BUCKET-NAME>/*"'
    filter_policy_action:
        requestParameters|contains: '"s3:GetObject"'
    filter_policy_effect:
        requestParameters|contains: '"Allow"'
    condition: selection_source and filter_tooling and filter_policy_resource and filter_policy_action and filter_policy_effect
falsepositives:
    - Valid usage of S3 Browser with accidental creation of default Inline IAM Policy without changing default S3 bucket name placeholder value
level: high""")
    output_rule = yaml.safe_load("""title: Suspicious IAM User Policy Creation
status: experimental
description: Detects creation of IAM user policies which may indicate malicious activity by threat actors such as GUI-vil who attempt persistence.
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
    - https://attack.mitre.org/techniques/T1098/003/
author: LLMCloudHunter
date: 2024/05/17
tags:
    - attack.persistence
    - attack.t1098
    - attack.t1098.003
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: PutUserPolicy
    selection_ioc_ip:
        sourceIPAddress:
            - 114.125.246.235
            - 182.1.229.252
            - 114.125.228.81
            - 114.125.232.189
            - 114.125.246.43
            - 114.125.245.53
            - 36.85.110.142
            - 114.125.229.197
            - 114.125.247.101
    selection_ioc_ua:
        userAgent|contains: S3 Browser 9.5.5 https://s3browser.com/
condition: selection and (selection_ioc_ip or selection_ioc_ua)
falsepositives:
    - Legitimate IAM user policy creation for administrative purposes
level: high""")

    entities, relationships = extract_entities_and_relationships([ground_truth_rule, output_rule])
    # entities, relationships = extract_entities_and_relationships(ground_truth_rule)
    print('hi')

    # results = compare_sigma_rules(ground_truth_rule, output_rule)
    # for key, value in results.items():
    #     print(key, value)



    # print_entities(rule_objects_list)
    # print_entity_sigma_field(rule_objects_list)
    # print_api_call_tactic(rule_objects_list)
    # print_api_call_technique(rule_objects_list)
    # print_api_call_sub_technique(rule_objects_list)
    # print_api_call_ioc(rule_objects_list)
    # print_api_call_other(rule_objects_list)


if __name__ == "__main__":
    main()
