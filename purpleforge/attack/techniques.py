"""ATT&CK technique database and lookup."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
from pathlib import Path


@dataclass
class Mitigation:
    """ATT&CK mitigation."""
    id: str
    name: str
    description: str


@dataclass
class DataSource:
    """ATT&CK data source."""
    name: str
    data_components: List[str]


@dataclass
class AttackTechnique:
    """ATT&CK technique with full details."""
    id: str
    name: str
    tactic: str
    description: str
    platforms: List[str] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    data_sources: List[DataSource] = field(default_factory=list)
    detection: str = ""
    url: str = ""
    sub_techniques: List[str] = field(default_factory=list)


# Embedded ATT&CK data for web/network security assessment techniques
ATTACK_TECHNIQUES: Dict[str, dict] = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration. Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet accessible open sockets.",
        "platforms": ["Windows", "Linux", "macOS", "Containers", "Network"],
        "mitigations": [
            {"id": "M1048", "name": "Application Isolation and Sandboxing", "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."},
            {"id": "M1050", "name": "Exploit Protection", "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."},
            {"id": "M1030", "name": "Network Segmentation", "description": "Architect sections of the network to isolate critical systems, functions, or resources."},
            {"id": "M1026", "name": "Privileged Account Management", "description": "Manage the creation, modification, use, and permissions associated to privileged accounts."},
            {"id": "M1051", "name": "Update Software", "description": "Perform regular software updates to mitigate exploitation risk."},
            {"id": "M1016", "name": "Vulnerability Scanning", "description": "Scan systems to identify potential vulnerabilities that could be exploited."}
        ],
        "data_sources": [
            {"name": "Application Log", "data_components": ["Application Log Content"]},
            {"name": "Network Traffic", "data_components": ["Network Traffic Content"]}
        ],
        "detection": "Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic. Web Application Firewalls may detect improper inputs attempting exploitation.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "mitigations": [
            {"id": "M1049", "name": "Antivirus/Antimalware", "description": "Use signatures or heuristics to detect malicious software."},
            {"id": "M1038", "name": "Execution Prevention", "description": "Block execution of code on a system through application control."},
            {"id": "M1040", "name": "Behavior Prevention on Endpoint", "description": "Use capabilities to prevent suspicious behavior patterns from occurring."},
            {"id": "M1026", "name": "Privileged Account Management", "description": "Manage the creation, modification, use, and permissions associated to privileged accounts."},
            {"id": "M1021", "name": "Restrict Web-Based Content", "description": "Restrict use of certain websites, block downloads/attachments."}
        ],
        "data_sources": [
            {"name": "Command", "data_components": ["Command Execution"]},
            {"name": "Module", "data_components": ["Module Load"]},
            {"name": "Process", "data_components": ["Process Creation", "Process Metadata"]},
            {"name": "Script", "data_components": ["Script Execution"]}
        ],
        "detection": "Monitor command-line arguments for unusual or suspicious execution. Monitor for suspicious file creation that could indicate script execution.",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "sub_techniques": ["T1059.001", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007"]
    },
    "T1059.007": {
        "id": "T1059.007",
        "name": "JavaScript",
        "tactic": "Execution",
        "description": "Adversaries may abuse JavaScript for execution. JavaScript (JS) is a platform-agnostic scripting language commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser. Adversaries may use various implementations of JS to execute various behaviors.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": [
            {"id": "M1040", "name": "Behavior Prevention on Endpoint", "description": "Use capabilities to prevent suspicious behavior patterns from occurring."},
            {"id": "M1038", "name": "Execution Prevention", "description": "Block execution of code on a system through application control."},
            {"id": "M1021", "name": "Restrict Web-Based Content", "description": "Restrict use of certain websites, block downloads/attachments."}
        ],
        "data_sources": [
            {"name": "Command", "data_components": ["Command Execution"]},
            {"name": "Module", "data_components": ["Module Load"]},
            {"name": "Process", "data_components": ["Process Creation"]},
            {"name": "Script", "data_components": ["Script Execution"]}
        ],
        "detection": "Monitor for events associated with scripting execution. Monitor for execution of JavaScript scripts.",
        "url": "https://attack.mitre.org/techniques/T1059/007/"
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic.",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "mitigations": [
            {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Use intrusion detection signatures to block traffic at network boundaries."}
        ],
        "data_sources": [
            {"name": "Network Traffic", "data_components": ["Network Traffic Content", "Network Traffic Flow"]}
        ],
        "detection": "Analyze network data for uncommon data flows. Monitor and analyze traffic patterns and packet inspection.",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "sub_techniques": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"]
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. HTTP/S traffic often traverses firewalls without much inspection.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": [
            {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Use intrusion detection signatures to block traffic at network boundaries."}
        ],
        "data_sources": [
            {"name": "Network Traffic", "data_components": ["Network Traffic Content", "Network Traffic Flow"]}
        ],
        "detection": "Analyze network data for unusual patterns. Analyze packet contents to detect communications that do not follow expected protocol behavior.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1087": {
        "id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS", "Google Workspace"],
        "mitigations": [
            {"id": "M1028", "name": "Operating System Configuration", "description": "Make configuration changes related to the operating system or common software."}
        ],
        "data_sources": [
            {"name": "Command", "data_components": ["Command Execution"]},
            {"name": "File", "data_components": ["File Access"]},
            {"name": "Process", "data_components": ["OS API Execution", "Process Creation"]}
        ],
        "detection": "Monitor processes and command-line arguments for actions that could be taken to gather information about accounts.",
        "url": "https://attack.mitre.org/techniques/T1087/",
        "sub_techniques": ["T1087.001", "T1087.002", "T1087.003", "T1087.004"]
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS", "Google Workspace", "Containers", "Network"],
        "mitigations": [
            {"id": "M1036", "name": "Account Use Policies", "description": "Configure features related to account use like login attempt lockouts."},
            {"id": "M1032", "name": "Multi-factor Authentication", "description": "Use two or more pieces of evidence to authenticate."},
            {"id": "M1027", "name": "Password Policies", "description": "Set and enforce secure password policies for accounts."}
        ],
        "data_sources": [
            {"name": "Application Log", "data_components": ["Application Log Content"]},
            {"name": "User Account", "data_components": ["User Account Authentication"]}
        ],
        "detection": "Monitor authentication logs for failed login attempts. Alert on high volumes of authentication failures.",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "sub_techniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"]
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "mitigations": [
            {"id": "M1042", "name": "Disable or Remove Feature or Program", "description": "Remove or deny access to unnecessary features and programs."},
            {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Use intrusion detection signatures to block traffic."},
            {"id": "M1030", "name": "Network Segmentation", "description": "Architect network to isolate critical systems."}
        ],
        "data_sources": [
            {"name": "Cloud Service", "data_components": ["Cloud Service Enumeration"]},
            {"name": "Command", "data_components": ["Command Execution"]},
            {"name": "Network Traffic", "data_components": ["Network Traffic Flow"]}
        ],
        "detection": "System and network discovery techniques normally occur throughout an operation as an adversary learns the environment.",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        "platforms": ["PRE"],
        "mitigations": [
            {"id": "M1056", "name": "Pre-compromise", "description": "This technique cannot be easily mitigated as it is based on behaviors performed outside of enterprise defenses."}
        ],
        "data_sources": [
            {"name": "Network Traffic", "data_components": ["Network Traffic Content", "Network Traffic Flow"]}
        ],
        "detection": "Monitor for suspicious network traffic from unexpected sources. Detection opportunities may be limited.",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "sub_techniques": ["T1595.001", "T1595.002", "T1595.003"]
    },
    "T1595.002": {
        "id": "T1595.002",
        "name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans check if the configuration of a target host/application is potentially vulnerable.",
        "platforms": ["PRE"],
        "mitigations": [
            {"id": "M1056", "name": "Pre-compromise", "description": "This technique cannot be easily mitigated."}
        ],
        "data_sources": [
            {"name": "Network Traffic", "data_components": ["Network Traffic Content", "Network Traffic Flow"]}
        ],
        "detection": "Monitor for suspicious traffic patterns that may be indicative of scanning.",
        "url": "https://attack.mitre.org/techniques/T1595/002/"
    },
    "T1189": {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. Multiple ways exist to deliver exploit code to a browser.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": [
            {"id": "M1048", "name": "Application Isolation and Sandboxing", "description": "Restrict execution of code to virtual environments."},
            {"id": "M1050", "name": "Exploit Protection", "description": "Use capabilities to detect and block exploit conditions."},
            {"id": "M1021", "name": "Restrict Web-Based Content", "description": "Restrict use of certain websites."},
            {"id": "M1051", "name": "Update Software", "description": "Perform regular software updates."}
        ],
        "data_sources": [
            {"name": "Application Log", "data_components": ["Application Log Content"]},
            {"name": "File", "data_components": ["File Creation"]},
            {"name": "Network Traffic", "data_components": ["Network Connection Creation", "Network Traffic Content"]},
            {"name": "Process", "data_components": ["Process Creation"]}
        ],
        "detection": "Firewalls and proxies can inspect URLs. Network intrusion detection systems may detect malicious code transfer.",
        "url": "https://attack.mitre.org/techniques/T1189/"
    },
    "T1203": {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": [
            {"id": "M1048", "name": "Application Isolation and Sandboxing", "description": "Restrict execution of code to virtual environments."},
            {"id": "M1050", "name": "Exploit Protection", "description": "Use capabilities to detect and block exploit conditions."}
        ],
        "data_sources": [
            {"name": "Application Log", "data_components": ["Application Log Content"]},
            {"name": "Process", "data_components": ["Process Creation"]}
        ],
        "detection": "Detecting software exploitation may be difficult depending on the tools available.",
        "url": "https://attack.mitre.org/techniques/T1203/"
    },
    "T1505": {
        "id": "T1505",
        "name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": [
            {"id": "M1047", "name": "Audit", "description": "Perform audits or scans of systems, permissions, etc."},
            {"id": "M1045", "name": "Code Signing", "description": "Enforce binary and application integrity."},
            {"id": "M1042", "name": "Disable or Remove Feature or Program", "description": "Remove unnecessary features."},
            {"id": "M1026", "name": "Privileged Account Management", "description": "Manage privileged account use."}
        ],
        "data_sources": [
            {"name": "Application Log", "data_components": ["Application Log Content"]},
            {"name": "File", "data_components": ["File Creation", "File Modification"]},
            {"name": "Network Traffic", "data_components": ["Network Traffic Content", "Network Traffic Flow"]},
            {"name": "Process", "data_components": ["Process Creation"]}
        ],
        "detection": "Consider monitoring application logs for abnormal behavior that may indicate suspicious installation of software components.",
        "url": "https://attack.mitre.org/techniques/T1505/",
        "sub_techniques": ["T1505.001", "T1505.002", "T1505.003", "T1505.004"]
    },
    "T1505.003": {
        "id": "T1505.003",
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server.",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "mitigations": [
            {"id": "M1042", "name": "Disable or Remove Feature or Program", "description": "Disable unnecessary features."},
            {"id": "M1018", "name": "User Account Management", "description": "Manage the creation, modification of user accounts."}
        ],
        "data_sources": [
            {"name": "Application Log", "data_components": ["Application Log Content"]},
            {"name": "File", "data_components": ["File Creation", "File Modification"]},
            {"name": "Network Traffic", "data_components": ["Network Traffic Content", "Network Traffic Flow"]},
            {"name": "Process", "data_components": ["Process Creation"]}
        ],
        "detection": "Web shells can be difficult to detect. File monitoring may detect changes to files in Web directories.",
        "url": "https://attack.mitre.org/techniques/T1505/003/"
    }
}


class AttackTechniqueDatabase:
    """Database of ATT&CK techniques with lookup and export capabilities."""

    def __init__(self):
        """Initialize technique database."""
        self.techniques: Dict[str, AttackTechnique] = {}
        self._load_techniques()

    def _load_techniques(self) -> None:
        """Load techniques from embedded data."""
        for tech_id, data in ATTACK_TECHNIQUES.items():
            mitigations = [
                Mitigation(**m) for m in data.get("mitigations", [])
            ]
            data_sources = [
                DataSource(**ds) for ds in data.get("data_sources", [])
            ]
            self.techniques[tech_id] = AttackTechnique(
                id=data["id"],
                name=data["name"],
                tactic=data["tactic"],
                description=data["description"],
                platforms=data.get("platforms", []),
                mitigations=mitigations,
                data_sources=data_sources,
                detection=data.get("detection", ""),
                url=data.get("url", ""),
                sub_techniques=data.get("sub_techniques", []),
            )

    def lookup(self, technique_id: str) -> Optional[AttackTechnique]:
        """
        Look up a technique by ID.

        Args:
            technique_id: ATT&CK technique ID (e.g., T1190)

        Returns:
            AttackTechnique or None if not found
        """
        return self.techniques.get(technique_id.upper())

    def get_mitigations(self, technique_id: str) -> List[Mitigation]:
        """Get mitigations for a technique."""
        tech = self.lookup(technique_id)
        return tech.mitigations if tech else []

    def get_data_sources(self, technique_id: str) -> List[DataSource]:
        """Get data sources for a technique."""
        tech = self.lookup(technique_id)
        return tech.data_sources if tech else []

    def get_all_techniques(self) -> List[AttackTechnique]:
        """Get all techniques."""
        return list(self.techniques.values())

    def get_techniques_by_tactic(self, tactic: str) -> List[AttackTechnique]:
        """Get techniques for a specific tactic."""
        return [t for t in self.techniques.values() if t.tactic.lower() == tactic.lower()]

    def export_navigator_layer(
        self,
        technique_ids: List[str],
        layer_name: str = "PurpleForge Assessment",
        description: str = "Techniques covered by assessment"
    ) -> dict:
        """
        Export ATT&CK Navigator layer JSON.

        Args:
            technique_ids: List of technique IDs to highlight
            layer_name: Layer name
            description: Layer description

        Returns:
            Navigator layer as dictionary
        """
        techniques_data = []
        for tech_id in technique_ids:
            tech = self.lookup(tech_id)
            if tech:
                techniques_data.append({
                    "techniqueID": tech.id,
                    "tactic": tech.tactic.lower().replace(" ", "-"),
                    "color": "#ff6666",  # Red for covered techniques
                    "comment": f"Covered by PurpleForge assessment",
                    "enabled": True,
                    "showSubtechniques": True
                })

        return {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": description,
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Network"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": techniques_data,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 1
            },
            "legendItems": [
                {
                    "label": "Covered by assessment",
                    "color": "#ff6666"
                }
            ],
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": True
        }

    def format_technique_report(self, technique_id: str) -> str:
        """
        Format technique information for report.

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            Formatted Markdown string
        """
        tech = self.lookup(technique_id)
        if not tech:
            return f"### {technique_id}\n*Technique not found in database*\n"

        lines = [
            f"### {tech.id} - {tech.name}",
            f"**Tactic:** {tech.tactic}",
            "",
            f"**Description:** {tech.description[:500]}{'...' if len(tech.description) > 500 else ''}",
            "",
            f"**Platforms:** {', '.join(tech.platforms)}",
            "",
        ]

        if tech.mitigations:
            lines.append("**Mitigations:**")
            for m in tech.mitigations:
                lines.append(f"- **{m.id}** - {m.name}: {m.description[:100]}...")
            lines.append("")

        if tech.data_sources:
            lines.append("**Detection Data Sources:**")
            for ds in tech.data_sources:
                components = ", ".join(ds.data_components)
                lines.append(f"- {ds.name}: {components}")
            lines.append("")

        if tech.detection:
            lines.append(f"**Detection Guidance:** {tech.detection[:300]}...")
            lines.append("")

        lines.append(f"**Reference:** [{tech.url}]({tech.url})")
        lines.append("")

        return "\n".join(lines)
