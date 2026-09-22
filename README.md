# Gmail IMAP Email Collector

A Python-based Gmail email collection tool that connects to Gmail using IMAP and continuously monitors the mailbox for newly received emails.

The tool collects email metadata, headers, security-related headers, message bodies, URLs, and domains, and stores the collected information in a JSONL file for further analysis.

## Features

- Gmail IMAP over SSL
- Gmail App Password authentication
- Configuration through `config.json`
- No credentials hardcoded in `main.py`
- Automatic detection of new emails
- INBOX monitoring
- SPAM/JUNK mailbox monitoring
- Duplicate email protection
- Full email header extraction
- Security header extraction
- Plain-text body extraction
- HTML body extraction
- URL extraction
- Domain extraction
- URL and domain counts
- Email collection timestamp
- JSONL-based email storage
- Tkinter graphical interface
- Start and Stop monitoring controls
- Real-time monitoring status

## Project Structure

```text
Gmail-IMAP-Email-Collector/
│
├── main.py
├── config.json
└── email.json
