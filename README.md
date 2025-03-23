# Advanced Keylogger with Secure Email Reporting
An all-in-one Python keylogger that logs keystrokes, captures clipboard data, gathers system info, and sends the logs via encrypted email attachments. For demonstration and legitimate monitoring only.
________________________________________
## Table of Contents
1.	Overview
2.	Features
3.	Installation & Setup
4.	Usage
5.	Configuration
6.	Future Improvements
________________________________________
## Overview
This project implements a Python-based keylogger that:
- Captures keyboard input (using pynput).
- Monitors the clipboard (Windows only).
- Collects basic system info (OS, IP, etc.).
- Encrypts the logs using AES (Fernet) and optionally RSA.
- Emails the encrypted logs as attachments to a configured address.
Disclaimer: Intended for educational and legitimately permitted uses. Unauthorized usage may be illegal.
________________________________________
## Features
- Keylogging: Logs keystrokes in continuous intervals.
- Clipboard & System Info: Gathers clipboard text and system details.
- Encryption: Implements AES for file encryption, plus optional RSA-based double encryption for the AES key.
- Automatic Email: Sends logs over SMTP (Gmail by default) at each logging interval.
- Offline Caching: Queues logs for later if sending fails.
- Stealth Options: Minimizes console presence, can attempt registry-based startup on Windows.
________________________________________
## Installation & Setup
1.	Clone this repository:
    git clone https://github.com/manavasnani/system-monitoring-keylogger.git
    cd system-monitoing-keylogger
2.	Install dependencies:
    pip install -r requirements.txt
3.	Configure Gmail (if applicable):
    Enable 2FA on your Google account.
    Create an App Password and use it instead of your normal Gmail password.
4.	Edit ****keylogger.py:
    Update EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENT with your credentials.
    Adjust LOG_INTERVAL, RUN_AT_STARTUP, or RSA keys as you see fit.
________________________________________
## Usage
1.	Run the Script:
    python keylogger.py
2.	Type in Another Window:
    Switch to a text editor or web browser and type. The script won’t capture keystrokes typed into its own console on Windows.
    At each interval (or when you press ESC in that window), logs finalize.
3.	Check Logs & Email:
    A logs folder will contain raw and encrypted log files.
    Encrypted files (.enc) and the RSA-encrypted AES keys (.key) are emailed automatically.
4.	Stop the Script:
    Press Ctrl + C in the console to terminate the script.
________________________________________
## Configuration
- LOG_INTERVAL: Adjust how often logs rotate and are sent.
- RUN_AT_STARTUP: If True, attempts to add itself to Windows registry.
- SENSITIVE_KEYWORDS: Trigger extra logging or labeling for certain typed keywords.
- RSA Key Generation: Script auto-creates rsa_private.pem and rsa_public.pem unless found.
________________________________________
## Future Improvements
- Periodic screenshots or webcam snapshots (with explicit consent)
- GUI or web dashboard to control logging intervals
- Enhanced cross-platform compatibility for Linux/Mac
- Real-time remote management & on-demand log retrieval
________________________________________
Use responsibly and ethically. Unauthorized deployment could be illegal.

