# CyberMoriarty

CyberMoriarty is an AI-driven pentesting tool designed to identify and exploit common vulnerabilities in target websites. It leverages machine learning and Metasploit to suggest and execute exploits, generating a detailed cybersecurity report.

## Features

- Resolves IP addresses of target websites.
- Scans for open ports and running services.
- Suggests exploits for detected vulnerabilities.
- Executes attacks using Machine Learning(RandomForestClassifier).
- Generates comprehensive cybersecurity reports.

## Prerequisites

- Python 3.6+
- Kali Linux or any Linux distribution with Metasploit installed.
- The following Python libraries:
  - `socket`
  - `requests`
  - `numpy`
  - `pandas`
  - `scikit-learn`
  - `tkinter`
  - `bs4`

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/CyberMoriarty.git
   cd CyberMoriarty
