import tkinter as tk
from tkinter import ttk, messagebox
import imaplib
import email
import json
import os
import threading
import time
import re
from html import unescape
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


# =========================================================
# Gmail Configuration
# =========================================================

IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(
    BASE_DIR,
    "config.json"
)

JSON_FILE = os.path.join(
    BASE_DIR,
    "email.json"
)

mail = None
monitoring = False
monitor_thread = None
start_time = None
EMAIL_ADDRESS = ""
APP_PASSWORD = ""

seen_ids = set()
mailbox_names = []


# =========================================================
# Load Configuration
# =========================================================

def load_config():

    global EMAIL_ADDRESS
    global APP_PASSWORD

    if not os.path.exists(CONFIG_FILE):

        messagebox.showerror(
            "Configuration Missing",
            "config.json was not found. Create it with your Gmail address and App Password."
        )

        return False

    try:

        with open(
            CONFIG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            config = json.load(file)

        EMAIL_ADDRESS = str(
            config.get(
                "email",
                ""
            )
        ).strip()

        APP_PASSWORD = str(
            config.get(
                "app_password",
                ""
            )
        ).strip()

        if not EMAIL_ADDRESS or not APP_PASSWORD:

            messagebox.showerror(
                "Invalid Configuration",
                "config.json must contain both 'email' and 'app_password'."
            )

            return False

        return True

    except json.JSONDecodeError:

        messagebox.showerror(
            "Invalid Configuration",
            "config.json contains invalid JSON."
        )

        return False

    except Exception as error:

        messagebox.showerror(
            "Configuration Error",
            str(error)
        )

        return False


# =========================================================
# Load Existing IDs
# =========================================================

def load_existing_ids():

    global seen_ids

    seen_ids = set()

    if not os.path.exists(JSON_FILE):
        return

    try:

        with open(
            JSON_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:

                    item = json.loads(line)

                    if "id" in item:
                        seen_ids.add(item["id"])

                except json.JSONDecodeError:

                    continue

    except Exception:

        seen_ids = set()


# =========================================================
# Save Email as JSONL
# =========================================================

def save_email(email_data):

    with open(
        JSON_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        json.dump(
            email_data,
            file,
            ensure_ascii=False
        )

        file.write("\n")


# =========================================================
# Decode Header
# =========================================================

def decode_header_value(value):

    if not value:
        return ""

    decoded_parts = email.header.decode_header(value)

    result = ""

    for part, encoding in decoded_parts:

        if isinstance(part, bytes):

            try:

                result += part.decode(
                    encoding or "utf-8",
                    errors="ignore"
                )

            except Exception:

                result += part.decode(
                    "utf-8",
                    errors="ignore"
                )

        else:

            result += part

    return result


# =========================================================
# Extract All Headers
# =========================================================

def extract_headers(message):

    headers = {}

    for name, value in message.items():

        decoded_value = decode_header_value(
            value
        )

        if name in headers:

            if isinstance(
                headers[name],
                list
            ):

                headers[name].append(
                    decoded_value
                )

            else:

                headers[name] = [
                    headers[name],
                    decoded_value
                ]

        else:

            headers[name] = decoded_value

    return headers


# =========================================================
# Security Headers
# =========================================================

def extract_security_headers(message):

    return {

        "authentication_results":
            decode_header_value(
                message.get(
                    "Authentication-Results",
                    ""
                )
            ),

        "received_spf":
            decode_header_value(
                message.get(
                    "Received-SPF",
                    ""
                )
            ),

        "dkim_signature":
            decode_header_value(
                message.get(
                    "DKIM-Signature",
                    ""
                )
            ),

        "arc_authentication_results":
            decode_header_value(
                message.get(
                    "ARC-Authentication-Results",
                    ""
                )
            ),

        "arc_seal":
            decode_header_value(
                message.get(
                    "ARC-Seal",
                    ""
                )
            ),

        "arc_message_signature":
            decode_header_value(
                message.get(
                    "ARC-Message-Signature",
                    ""
                )
            )
    }


# =========================================================
# Extract Plain Text + HTML Body
# =========================================================

def get_email_content(message):

    plain_body = ""
    html_body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            disposition = str(
                part.get(
                    "Content-Disposition",
                    ""
                )
            )

            if "attachment" in disposition.lower():
                continue

            payload = part.get_payload(
                decode=True
            )

            if not payload:
                continue

            text = payload.decode(
                "utf-8",
                errors="ignore"
            )

            if content_type == "text/plain":

                plain_body += text

            elif content_type == "text/html":

                html_body += text

    else:

        payload = message.get_payload(
            decode=True
        )

        if payload:

            text = payload.decode(
                "utf-8",
                errors="ignore"
            )

            if message.get_content_type() == "text/html":

                html_body = text

            else:

                plain_body = text

    return (
        plain_body.strip(),
        html_body.strip()
    )


# =========================================================
# Extract URLs
# =========================================================

def extract_urls(text):

    if not text:
        return []

    # Remove HTML tags
    clean_text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    clean_text = unescape(
        clean_text
    )

    # Find HTTP / HTTPS URLs
    url_pattern = r'https?://[^\s<>"\'\]\)]+'

    urls = re.findall(
        url_pattern,
        clean_text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        if url not in cleaned_urls:

            cleaned_urls.append(
                url
            )

    return cleaned_urls


# =========================================================
# Extract URL Domains
# =========================================================

def extract_domains(urls):

    domains = []

    for url in urls:

        match = re.search(
            r"https?://([^/:?#]+)",
            url,
            flags=re.IGNORECASE
        )

        if match:

            domain = match.group(1).lower()

            if domain not in domains:

                domains.append(
                    domain
                )

    return domains


# =========================================================
# Check Email Time
# =========================================================

def is_new_email(message):

    date_header = message.get(
        "Date",
        ""
    )

    if not date_header:
        return False

    try:

        email_time = parsedate_to_datetime(
            date_header
        )

        if email_time.tzinfo is None:

            email_time = email_time.replace(
                tzinfo=timezone.utc
            )

        return email_time > start_time

    except Exception:

        return False


# =========================================================
# Process Email
# =========================================================

def process_email(email_id, mailbox_name=None):

    global mail

    try:

        status, data = mail.fetch(
            email_id,
            "(RFC822)"
        )

        if status != "OK":
            return

        raw_email = None

        for item in data:
            if isinstance(item, tuple) and len(item) > 1:
                raw_email = item[1]
                break

        if not raw_email:
            return

        message = email.message_from_bytes(
            raw_email
        )

        # Ignore old emails
        if not is_new_email(message):
            return

        # -------------------------------------------------
        # Message ID
        # -------------------------------------------------

        message_id = message.get(
            "Message-ID",
            ""
        ).strip()

        if not message_id:

            message_id = email_id.decode(
                "utf-8",
                errors="ignore"
            )

        # -------------------------------------------------
        # Duplicate Protection
        # -------------------------------------------------

        if message_id in seen_ids:
            return

        # -------------------------------------------------
        # Basic Information
        # -------------------------------------------------

        sender = decode_header_value(
            message.get(
                "From",
                ""
            )
        )

        receiver = decode_header_value(
            message.get(
                "To",
                ""
            )
        )

        cc = decode_header_value(
            message.get(
                "Cc",
                ""
            )
        )

        bcc = decode_header_value(
            message.get(
                "Bcc",
                ""
            )
        )

        reply_to = decode_header_value(
            message.get(
                "Reply-To",
                ""
            )
        )

        return_path = decode_header_value(
            message.get(
                "Return-Path",
                ""
            )
        )

        subject = decode_header_value(
            message.get(
                "Subject",
                ""
            )
        )

        date = decode_header_value(
            message.get(
                "Date",
                ""
            )
        )

        content_type = decode_header_value(
            message.get(
                "Content-Type",
                ""
            )
        )

        mime_version = decode_header_value(
            message.get(
                "MIME-Version",
                ""
            )
        )

        # -------------------------------------------------
        # Full Headers
        # -------------------------------------------------

        all_headers = extract_headers(
            message
        )

        # -------------------------------------------------
        # Security Headers
        # -------------------------------------------------

        security_headers = extract_security_headers(
            message
        )

        # -------------------------------------------------
        # Body
        # -------------------------------------------------

        plain_body, html_body = get_email_content(
            message
        )

        # -------------------------------------------------
        # URL Extraction
        # -------------------------------------------------

        urls = extract_urls(
            plain_body
        )

        # If plain text has no URLs, check HTML
        if not urls:

            urls = extract_urls(
                html_body
            )

        domains = extract_domains(
            urls
        )

        # -------------------------------------------------
        # Email JSON Event
        # -------------------------------------------------

        email_data = {

            "event_type": "email",

            "mailbox": mailbox_name or "INBOX",

            "id": message_id,

            "imap_id": email_id.decode(
                "utf-8",
                errors="ignore"
            ),

            "sender": sender,

            "to": receiver,

            "cc": cc,

            "bcc": bcc,

            "reply_to": reply_to,

            "return_path": return_path,

            "subject": subject,

            "date": date,

            "body": plain_body,

            "html_body": html_body,

            "urls": urls,

            "url_count": len(urls),

            "domains": domains,

            "domain_count": len(domains),

            "content_type": content_type,

            "mime_version": mime_version,

            "security_headers":
                security_headers,

            "headers":
                all_headers,

            "collected_at":
                datetime.now(
                    timezone.utc
                ).isoformat()
        }

        # -------------------------------------------------
        # Save
        # -------------------------------------------------

        save_email(
            email_data
        )

        seen_ids.add(
            message_id
        )

        # -------------------------------------------------
        # GUI Update
        # -------------------------------------------------

        root.after(
            0,
            lambda: new_email_detected(
                sender,
                subject,
                len(urls)
            )
        )

    except Exception:

        root.after(
            0,
            lambda: status_label.config(
                text="Status: Email processing error"
            )
        )


# =========================================================
# GUI Notification
# =========================================================

def new_email_detected(
    sender,
    subject,
    url_count
):

    status_label.config(
        text="Status: New email received ✓"
    )

    email_list.insert(
        0,
        f"NEW EMAIL | {sender} | {subject} | URLs: {url_count}"
    )


# =========================================================
# Gmail Monitor
# =========================================================

def get_mailboxes():

    global mail

    folders = []

    try:
        status, data = mail.list()

        if status != "OK":
            return ["INBOX"]

        for item in data:
            if not item:
                continue

            line = item.decode("utf-8", errors="ignore") if isinstance(item, bytes) else str(item)

            quoted = re.findall(r'"([^"]*)"', line)

            if quoted:
                name = quoted[-1]
            else:
                parts = line.rsplit(" ", 1)
                if len(parts) != 2:
                    continue
                name = parts[-1].strip('"')

            flags_match = re.search(r"\\((.*?)\\)", line)
            flags = flags_match.group(1).upper() if flags_match else ""

            upper_name = name.upper()

            if (
                upper_name == "INBOX"
                or "\\SPAM" in flags
                or "\\JUNK" in flags
                or "SPAM" in upper_name
                or "JUNK" in upper_name
            ):
                if name not in folders:
                    folders.append(name)

    except Exception:
        pass

    if not any(name.upper() == "INBOX" for name in folders):
        folders.insert(0, "INBOX")

    return folders


def process_mailbox(mailbox_name):

    try:

        status, _ = mail.select(
            f'"{mailbox_name}"'
        )

        if status != "OK":
            status, _ = mail.select(
                mailbox_name
            )

        if status != "OK":
            return

        status, messages = mail.search(
            None,
            "ALL"
        )

        if status != "OK" or not messages:
            return

        email_ids = messages[0].split()

        for email_id in email_ids[-10:]:

            if not monitoring:
                break

            process_email(
                email_id,
                mailbox_name
            )

    except Exception:
        pass


def monitor_gmail():

    global monitoring
    global mailbox_names

    while monitoring:

        try:

            mailbox_names = get_mailboxes()

            for mailbox_name in mailbox_names:

                if not monitoring:
                    break

                process_mailbox(
                    mailbox_name
                )

            if not monitoring:
                break

            root.after(
                0,
                lambda: status_label.config(
                    text="Status: Monitoring INBOX + SPAM ✓"
                )
            )

            time.sleep(5)

        except Exception:

            if monitoring:

                root.after(
                    0,
                    lambda: status_label.config(
                        text="Status: Monitoring error"
                    )
                )

                time.sleep(5)

    root.after(
        0,
        lambda: status_label.config(
            text="Status: Monitoring stopped"
        )
    )


# =========================================================
# Start Monitoring
# =========================================================

def start_monitoring():

    global monitoring
    global monitor_thread
    global start_time

    if mail is None:

        messagebox.showwarning(
            "Not Connected",
            "Connect to Gmail first."
        )

        return

    if monitoring:
        return

    # Exact start time
    start_time = datetime.now(
        timezone.utc
    )

    monitoring = True

    start_button.config(
        state="disabled"
    )

    stop_button.config(
        state="normal"
    )

    status_label.config(
        text="Status: Monitoring new emails..."
    )

    email_list.insert(
        0,
        ">>> Monitoring started. INBOX + SPAM monitored. Old emails ignored."
    )

    monitor_thread = threading.Thread(
        target=monitor_gmail,
        daemon=True
    )

    monitor_thread.start()


# =========================================================
# Stop Monitoring
# =========================================================

def stop_monitoring():

    global monitoring

    monitoring = False

    start_button.config(
        state="normal"
    )

    stop_button.config(
        state="disabled"
    )

    status_label.config(
        text="Status: Stopping..."
    )


# =========================================================
# Connect Gmail
# =========================================================

def connect_gmail():

    global mail

    if not load_config():

        return

    try:

        status_label.config(
            text="Status: Connecting..."
        )

        root.update()

        mail = imaplib.IMAP4_SSL(
            IMAP_SERVER,
            IMAP_PORT
        )

        mail.login(
            EMAIL_ADDRESS,
            APP_PASSWORD
        )

        load_existing_ids()

        global mailbox_names
        mailbox_names = get_mailboxes()

        status_label.config(
            text="Status: Connected ✓"
        )

        start_button.config(
            state="normal"
        )

        messagebox.showinfo(
            "Connected",
            "Gmail connected successfully!"

        )

    except Exception as error:

        mail = None

        status_label.config(
            text="Status: Connection Failed"
        )

        messagebox.showerror(
            "Connection Failed",
            str(error)
        )


# =========================================================
# GUI
# =========================================================

root = tk.Tk()

root.title(
    "Gmail IMAP Email Collector"
)

root.geometry(
    "700x600"
)

root.resizable(
    False,
    False
)


# =========================================================
# Title
# =========================================================

title_label = tk.Label(
    root,
    text="Gmail IMAP Email Collector",
    font=("Arial", 22, "bold")
)

title_label.pack(
    pady=20
)


# =========================================================
# Gmail Address
# =========================================================

email_label = tk.Label(
    root,
    text="Gmail Address"
)

email_label.pack()


email_entry = ttk.Entry(
    root,
    width=60
)

load_config()

email_entry.insert(
    0,
    EMAIL_ADDRESS
)

email_entry.config(
    state="readonly"
)

email_entry.pack(
    pady=7
)


# =========================================================
# Credentials
# =========================================================

credential_label = tk.Label(
    root,
    text="Credentials are loaded securely from config.json"
)

credential_label.pack(
    pady=(8, 0)
)


# =========================================================
# Connect
# =========================================================

connect_button = ttk.Button(
    root,
    text="Connect Gmail",
    command=connect_gmail
)

connect_button.pack(
    pady=10
)


# =========================================================
# Start Monitoring
# =========================================================

start_button = ttk.Button(
    root,
    text="Start Monitoring",
    command=start_monitoring,
    state="disabled"
)

start_button.pack(
    pady=5
)


# =========================================================
# Stop Monitoring
# =========================================================

stop_button = ttk.Button(
    root,
    text="Stop Monitoring",
    command=stop_monitoring,
    state="disabled"
)

stop_button.pack(
    pady=5
)


# =========================================================
# Status
# =========================================================

status_label = tk.Label(
    root,
    text="Status: Not Connected",
    font=("Arial", 11)
)

status_label.pack(
    pady=10
)


# =========================================================
# Activity List
# =========================================================

list_frame = tk.Frame(
    root
)

list_frame.pack(
    padx=20,
    pady=10,
    fill="both",
    expand=True
)


scrollbar = ttk.Scrollbar(
    list_frame
)

scrollbar.pack(
    side="right",
    fill="y"
)


email_list = tk.Listbox(
    list_frame,
    width=95,
    height=12,
    yscrollcommand=scrollbar.set
)

email_list.pack(
    side="left",
    fill="both",
    expand=True
)


scrollbar.config(
    command=email_list.yview
)


# =========================================================
# Start Application
# =========================================================

root.mainloop()